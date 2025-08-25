// Copyright 2024, 2025 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	"github.com/UNO-SOFT/filecache"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	"github.com/tgulacsi/imapclient/graph"
)

func (p *proxy) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	return &session{
			p:    p,
			conn: conn, idm: p.idm,
		},
		&imapserver.GreetingData{PreAuth: false},
		nil
}

type session struct {
	cl            graph.GraphMailClient
	p             *proxy
	conn          *imapserver.Conn
	folders       map[string]*Folder
	folderID      string
	idm           *uidMap
	userID        string
	mboxDeltaLink string
	users         []graph.User
}

func (s *session) Folder(mailbox string, clean bool) *Folder {
	if clean {
		mailbox = cleanMailbox(mailbox)
	}
	s.p.mu.RLock()
	F := s.folders[mailbox]
	s.p.mu.RUnlock()
	return F
}

func (s *session) logger() *slog.Logger { return s.p.logger() }

var _ imapserver.SessionIMAP4rev2 = (*session)(nil)

func (s *session) Close() error {
	conn := s.conn
	s.cl, s.conn, s.p, s.users = graph.GraphMailClient{}, nil, nil, nil
	if conn == nil {
		return nil
	}
	conn.Bye("QUIT")
	if nc := conn.NetConn(); nc != nil {
		nc.Close()
	}
	return nil
}

// Not authenticated state

// Login with username\x0AtenantID, clientSecret
func (s *session) Login(username, password string) error {
	user, tenantID, ok := strings.Cut(username, "\x0A")
	if !ok {
		if user, tenantID, ok = strings.Cut(username, ","); !ok {
			return fmt.Errorf("%w: username is missing \\x00tenantID: %q", imapserver.ErrAuthFailed, username)
		}
	}
	clientSecret := password
	logger := s.logger().With("username", username, "password", password,
		"user", user, "tenantID", tenantID, "clientID", s.p.clientID, "clientSecretLen", len(clientSecret))
	s.userID = ""
	ctx, cancel := context.WithTimeout(s.p.ctx, 3*time.Minute)
	defer cancel()
	var err error
	if s.cl, s.users, s.folders, err = s.p.connect(ctx, tenantID, clientSecret); err != nil {
		logger.Error("connect", "error", err)
		return fmt.Errorf("%w: %w", err, imapserver.ErrAuthFailed)
	}
	for _, u := range s.users {
		logger.Debug("user", "u", u)
		if id := u.GetId(); (id != nil && *id == user) ||
			(u.GetDisplayName() != nil && strings.EqualFold(*u.GetDisplayName(), user)) ||
			(u.GetEmployeeId() != nil && string(*u.GetEmployeeId()) == user) ||
			(u.GetMail() != nil && strings.EqualFold(string(*u.GetMail()), user)) ||
			(u.GetUserPrincipalName() != nil && strings.EqualFold(string(*u.GetUserPrincipalName()), user)) {
			s.userID = *id
			break
		}
	}
	if s.userID == "" {
		if len(s.users) != 1 {
			logger.Error("no user found", "users", s.users)
			return fmt.Errorf("user %q not found: %w", user, imapserver.ErrAuthFailed)
		}
		logger.Warn("user not found", "user", user, "users", s.users)
		s.userID = *s.users[0].GetId()
	}
	s.p.mu.Lock()
	for k, vv := range graph.WellKnownFolders {
		ck := cleanMailbox(k)
		if s.folders[ck] == nil {
			F := Folder{Mailbox: k}
			if F.Folder, err = s.cl.GetFolder(ctx, ck); err != nil {
				if errors.Is(err, graph.ErrNotFound) {
					continue
				}
				return err
			}
			if F.Folder == nil || F.Folder.GetId() == nil {
				continue
			}
			s.folders[ck] = &F
			for _, v := range vv {
				cv := cleanMailbox(v)
				if s.folders[cv] == nil {
				}
				F := Folder{Mailbox: k}
				if F.Folder, err = s.cl.GetFolder(ctx, v); err != nil {
					if errors.Is(err, graph.ErrNotFound) {
						continue
					}
					return err
				}
				if F.Folder == nil || F.Folder.GetId() == nil {
					continue
				}
				s.folders[cv] = &F
			}
		}
	}
	s.p.mu.Unlock()

	logger.Info("Login succeeded", "userID", s.userID)
	start := time.Now()
	err = s.fetchMailboxes(ctx, nil, false)
	s.p.mu.RLock()
	count := len(s.folders)
	s.p.mu.RUnlock()
	logger.Info("fetchMailboxes", "dur", time.Since(start).String(), "count", count)
	return err
}

// Authenticated state
func (s *session) Namespace() (*imap.NamespaceData, error) {
	if len(s.users) == 0 {
		return nil, imapserver.ErrAuthFailed
	}
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Prefix: "", Delim: delim}}}, nil
}

func cleanMailbox(s string) string {
	if len(s) == 36 && strings.Count(s, "-") == 4 && strings.IndexFunc(s, func(r rune) bool { return !('0' <= r && r <= '9' || r == '-' || 'a' <= r && r <= 'f') }) < 0 ||
		len(s) == 120 && s[len(s)-1] == '=' {
		return s
	}
	return strings.ToLower(strings.Trim(s, delimS))
}

func (s *session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	key := cleanMailbox(mailbox)
	logger := s.logger().With("mailbox", key)
	logger.Info("Select", "options", options)

	dn, _ := path.Split(mailbox)
	if dn != "" {
		dn += delimS
	}
	dirs := strings.Split(path.Clean(mailbox), delimS)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	root := s.Folder(key, false)
	if root == nil ||
		root.GetId() == nil || *root.GetId() == "" {
		logger.Warn("no folder", "key", key)
		if err := s.fetchMailboxes(ctx, dirs, true); err != nil {
			return nil, err
		}
		root = s.Folder(key, false)
	}
	if root == nil || root.GetId() == nil {
		logger.Warn("no folder", "key", key)
		s.p.mu.RLock()
		keys := maps.Keys(s.folders)
		s.p.mu.RUnlock()
		slices.Sort(keys)
		s.p.mu.RLock()
		for _, k := range keys {
			logger.Warn("have", "key", k, "folderID", s.folders[k].GetId())
		}
		s.p.mu.RUnlock()
		logger.Error("mailboxes", "have", keys, "root.id", root.GetId(), "root.tic", root.GetTotalItemCount(), "root", graph.JSON{root})
		return nil, fmt.Errorf("Select did not found root: %s", mailbox)
	}
	s.folderID, s.mboxDeltaLink = *root.GetId(), ""

	var total, unread, i0 uint32
	if i := root.GetTotalItemCount(); i != nil {
		total = uint32(*i)
	}
	if i := root.GetUnreadItemCount(); i != nil {
		unread = uint32(*i)
	}
	uidNext := s.idm.uidNext(s.folderID)
	return &imap.SelectData{
		NumMessages: total,
		UIDValidity: s.idm.uidValidity, UIDNext: uidNext,
		List: &imap.ListData{
			Delim: delim, Mailbox: *root.GetDisplayName(),
			Status: &imap.StatusData{
				Mailbox:     *root.GetDisplayName(),
				NumMessages: &total,
				NumUnseen:   &unread,
				NumRecent:   &i0, NumDeleted: &i0,
				UIDNext: uidNext, UIDValidity: s.idm.uidValidity,
			}},
	}, nil
}

func (s *session) fetchMailboxes(ctx context.Context, dirs []string, count bool) error {
	logger := s.logger()
	slcts := []string{
		"displayName", "ID", "parentFolderId", //"wellKnownName",
		"totalItemCount", "unreadItemCount",
	}
	if !count {
		slcts = slcts[:len(slcts)-2]
	}
	qry := graph.Query{Select: slcts}
	folders, err := s.cl.ListMailFolders(ctx, s.userID, qry)
	if err != nil {
		return err
	}
	var fetchSubfolders func(Folder, []string) error
	fetchSubfolders = func(parent Folder, dirs []string) error {
		folders, err := s.cl.ListChildFolders(ctx, s.userID, *parent.GetId(), false, qry)
		if err != nil {
			return err
		} else if len(folders) == 0 {
			return nil
		}
		key := cleanMailbox(parent.Mailbox) + delimS
		for _, f := range folders {
			if f == nil || f.GetId() == nil {
				logger.Warn("zero folder", "f", f)
				continue
			}
			f.SetParentFolderId(parent.GetId())
			F := Folder{Folder: f, Mailbox: key + *f.GetDisplayName()}
			// logger.Warn("fetchSubfolders", "dn", *f.GetDisplayName(), "id", *f.GetId())
			s.p.mu.Lock()
			s.folders[key+cleanMailbox(*f.GetDisplayName())] = &F
			s.folders[*f.GetId()] = &F
			s.p.mu.Unlock()

			if len(dirs) == 0 ||
				strings.EqualFold(*f.GetDisplayName(), dirs[0]) && len(dirs) > 1 {
				dirs := dirs
				if len(dirs) != 0 {
					dirs = dirs[1:]
				}
				if err = fetchSubfolders(F, dirs); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, f := range folders {
		if f == nil || f.GetId() == nil {
			logger.Warn("zero folder", "f", f)
			continue
		}
		F := Folder{Folder: f, Mailbox: *f.GetDisplayName()}
		s.p.mu.Lock()
		s.folders[cleanMailbox(F.Mailbox)] = &F
		s.folders[*F.GetId()] = &F
		s.p.mu.Unlock()
		if len(dirs) == 0 || *f.GetDisplayName() == dirs[0] {
			dirs := dirs
			if len(dirs) != 0 {
				dirs = dirs[1:]
			}
			if err = fetchSubfolders(F, dirs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *session) Create(mailbox string, options *imap.CreateOptions) error {
	logger := s.logger().With("mailbox", mailbox)
	if s.Folder(mailbox, true) != nil {
		logger.Warn("already exist")
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	dirs := strings.Split(path.Clean(mailbox), "/")
	var parent graph.Folder
	for i := range dirs {
		dir := cleanMailbox(strings.Join(dirs[:i+1], delimS))
		F := s.Folder(dir, false)
		if F != nil && F.GetId() != nil && *(F.GetId()) != "" {
			parent = F.Folder
			continue
		}
		if i == 0 {
			folder, err := s.cl.CreateFolder(ctx, s.userID, dirs[0])
			if err == nil {
				F := Folder{Folder: folder, Mailbox: dirs[0]}
				s.p.mu.Lock()
				s.folders[dir] = &F
				s.folders[*F.GetId()] = &F
				s.p.mu.Unlock()
			} else if strings.Contains(err.Error(), "ErrorFolderExists") {
				// folder = s.folders[dir].Folder
				s.p.mu.RLock()
				have := maps.Keys(s.folders)
				s.p.mu.RUnlock()
				logger.Error("ERR already exist", "dir", dirs[:i+1], "id", *folder.GetId(), "have", have)
				return s.fetchMailboxes(ctx, nil, false)
			} else {
				return err
			}
			parent = folder
			continue
		}
		if parent.GetId() == nil || *parent.GetId() == "" {
			s.p.mu.RLock()
			have := maps.Keys(s.folders)
			s.p.mu.RUnlock()
			return fmt.Errorf("nil parent for %q; have: %q", dirs[:i+1], have)
		}
		folder, err := s.cl.CreateChildFolder(
			ctx, s.userID, *parent.GetId(), dirs[i],
		)
		if err == nil {
			F := Folder{Folder: folder, Mailbox: strings.Join(dirs[:i+1], delimS)}
			s.p.mu.Lock()
			s.folders[dir] = &F
			s.folders[*F.GetId()] = &F
			s.p.mu.Unlock()
		} else if strings.Contains(err.Error(), "ErrorFolderExists") {
			logger.Warn("already exists", "dir", dir)
			folder = s.Folder(dir, false).Folder
		} else {
			return err
		}
		parent = folder
	}
	return nil
}

func (s *session) Delete(mailbox string) error {
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	F := s.Folder(mailbox, true)
	err := s.cl.DeleteFolder(ctx, s.userID, *F.GetId())
	if err != nil {
		P := s.Folder(path.Dir(mailbox), true)
		err = s.cl.DeleteChildFolder(ctx, s.userID, *P.GetId(), *F.GetId())
	}
	cancel()
	return err
}

var ErrNotImplemented = errors.New("not implemented")

func (s *session) Rename(mailbox, newName string, opts *imap.RenameOptions) error {
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	err := s.cl.RenameFolder(ctx, s.userID, *s.Folder(mailbox, true).GetId(), newName)
	cancel()
	return err
}

func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error { return nil }

func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error { <-stop; return nil }
func (s *session) Subscribe(mailbox string) error                              { return ErrNotImplemented }
func (s *session) Unsubscribe(mailbox string) error                            { return ErrNotImplemented }

// List
//
// The LIST command returns a subset of mailbox names from the complete set of all mailbox names available to the client.
// An empty ("" string) reference name argument indicates that the mailbox name is interpreted as by SELECT.
// The returned mailbox names MUST match the supplied mailbox name pattern(s).
// A non-empty reference name argument is the name of a mailbox or a level of mailbox hierarchy,
// and it indicates the context in which the mailbox name is interpreted.
// Clients SHOULD use the empty reference argument.
// In the basic syntax only, an empty ("" string) mailbox name argument is a special request to return the hierarchy delimiter and the root name of the name given in the reference.
// The value returned as the root MAY be the empty string if the reference is non-rooted or is an empty string.
// In all cases, a hierarchy delimiter (or NIL if there is no hierarchy) is returned. This permits a client to get the hierarchy delimiter (or find out that the mailbox names are flat) even when no mailboxes by that name currently exist.
// In the extended syntax, any mailbox name arguments that are empty strings are ignored.
// There is no special meaning for empty mailbox names when the extended syntax is used.
// The reference and mailbox name arguments are interpreted into a canonical form that represents an unambiguous left-to-right hierarchy.
// The returned mailbox names will be in the interpreted form, which we call a "canonical LIST pattern": the canonical pattern constructed internally by the server from the reference and mailbox name arguments.
func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	logger := s.logger().With("ref", ref, "patterns", patterns)
	logger.Info("List", "options", options)
	zero := imap.ListData{Delim: delim}
	data := zero
	ref = strings.Trim(ref, delimS)
	if ref == "" && len(patterns) == 0 {
		data.Mailbox = ""
		return w.WriteList(&data)
	}
	var parentID string
	qry := graph.Query{Select: []string{
		"displayName", "Id", "parentFolderId", //"wellKnownName",
		"totalItemCount", "unreadItemCount"}}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	var found []graph.Folder
	if ref == "" {
		folders, err := s.cl.ListMailFolders(ctx, s.userID, qry)
		if err != nil {
			return err
		}
		for _, f := range folders {
			for _, pat := range patterns {
				if imapserver.MatchList(*f.GetDisplayName(), delim, ref, pat) {
					found = append(found, f)
				}
			}
		}
	} else {
		dirs := strings.Split(cleanMailbox(ref), delimS)
		for i := range dirs {
			dir := strings.Join(dirs[:i+1], delimS)
			if folder := s.Folder(dir, false); folder.GetId() == nil || *folder.GetId() == "" {
				qry := qry
				ed := graph.EscapeSingleQuote(dirs[i])
				qry.Filter = "displayName:" + ed
				var folders []graph.Folder
				var err error
				if parentID == "" {
					folders, err = s.cl.ListMailFolders(ctx, s.userID, qry)
				} else {
					folders, err = s.cl.ListChildFolders(ctx, s.userID, parentID, false, qry)
				}
				if err != nil {
					return err
				}
				if len(folders) == 0 {
					return fmt.Errorf("no %q folder under %q", dirs[i], strings.Join(dirs[:i], delimS))
				}
				logger.Debug("List ListFolders", "folders", folders, "qry", qry)
				parentID = *folders[0].GetId()
			}
		}
		folders, err := s.cl.ListChildFolders(ctx, s.userID, parentID, false, qry)
		if err != nil {
			return err
		}
		for _, f := range folders {
			for _, pat := range patterns {
				if name := ref + delimS + *f.GetDisplayName(); imapserver.MatchList(name, delim, ref, pat) {
					found = append(found, f)
				}
			}
		}
	}
	logger.Debug("List", "found", found)

	folders := make(map[string]graph.Folder, len(found))
	for i, f := range found {
		if f.GetId() != nil && *f.GetId() != "" {
			folders[*f.GetId()] = found[i]
		}
	}
	names := make(map[string]string)
	var parts []string
	for _, f := range found {
		if f.GetId() == nil || *f.GetId() == "" ||
			names[*f.GetId()] != "" {
			continue
		}
		if f.GetParentFolderId() == nil || *f.GetParentFolderId() == "" || strings.EqualFold(*f.GetDisplayName(), "Inbox") {
			names[*f.GetId()] = *f.GetDisplayName()
			continue
		}
		if parent := names[*f.GetParentFolderId()]; parent != "" {
			names[*f.GetId()] = parent + delimS + *f.GetDisplayName()
			continue
		}
		parts = append(parts[:0], *f.GetDisplayName())
		for p := folders[*f.GetParentFolderId()]; p != nil; p = folders[*p.GetParentFolderId()] {
			if p == nil {
				break
			}
			if nm := names[*p.GetId()]; nm != "" {
				parts = append(parts, nm)
				break
			}
			parts = append(parts, *p.GetDisplayName())
			logger.Info("p", *p.GetId(), parts)
			if p.GetParentFolderId() == nil || *p.GetParentFolderId() == "" {
				break
			}
		}
		if len(parts) == 1 {
			names[*f.GetId()] = parts[0]
			continue
		}
		logger.Info("name", "f", *f.GetId(), "parts", parts)
		slices.Reverse(parts)
		names[*f.GetId()] = strings.Join(parts, delimS)
	}

	var i0 uint32
	// s.logger().Debug("found", "n", len(found), "m", len(names), "names", names)
	for _, f := range found {
		total := uint32(*f.GetTotalItemCount())
		unread := uint32(*f.GetUnreadItemCount())
		data = zero
		data.Mailbox = names[*f.GetId()]
		data.Status = &imap.StatusData{
			Mailbox:     names[*f.GetId()],
			NumMessages: &total,
			NumUnseen:   &unread,
			NumRecent:   &i0, NumDeleted: &i0,
			UIDNext:     s.idm.uidNext(*f.GetId()),
			UIDValidity: s.idm.uidValidity,
		}
		logger.Debug("list", "data", data)
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}

	return nil
}

func (s *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	logger := s.logger().With("mailbox", mailbox)
	logger.Info("Status", "options", options)
	dn, bn := path.Split(mailbox)
	qry := graph.Query{Select: []string{
		"id", "displayName", "totalItemCount", "unreadItemCount",
	}}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	var err error
	var folders []graph.Folder
	if dn == "" {
		folders, err = s.cl.ListMailFolders(ctx, s.userID, qry)
	} else {
		folders, err = s.cl.ListChildFolders(ctx, s.userID, *s.Folder(path.Dir(mailbox), true).GetId(), false, qry)
	}
	cancel()
	if err != nil {
		logger.Error("Select", "qry", qry, "error", err)
		return nil, err
	}
	var i0 uint32
	for _, f := range folders {
		if !strings.EqualFold(*f.GetDisplayName(), bn) {
			continue
		}
		total := uint32(*f.GetTotalItemCount())
		unread := uint32(*f.GetUnreadItemCount())
		return &imap.StatusData{
			Mailbox:     mailbox,
			NumMessages: &total,
			NumUnseen:   &unread,
			NumRecent:   &i0, NumDeleted: &i0,
			UIDNext: s.idm.uidNext(*f.GetId()),
			// A good UIDVALIDITY value to use is a 32-bit representation of the current date/time when the value is assigned:
			UIDValidity: s.idm.uidValidity,
		}, err
	}
	return nil, fmt.Errorf("folder %q is not found under %q", bn, dn)
}

func (s *session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	M, err := gomessage.Read(r)
	if err != nil {
		return nil, err
	}
	froms, _ := graphAddressList(M.Header.FieldsByKey("From"))
	if err != nil {
		return nil, err
	}
	to, _ := graphAddressList(M.Header.FieldsByKey("To"))
	cc, _ := graphAddressList(M.Header.FieldsByKey("Cc"))
	bcc, _ := graphAddressList(M.Header.FieldsByKey("Bcc"))
	var buf strings.Builder
	if _, err := io.Copy(&buf, M.Body); err != nil {
		return nil, err
	}
	msg := graph.NewMessage()
	if subj := M.Header.Get("Subject"); subj != "" {
		msg.SetSubject(&subj)
	}
	msg.SetFrom(froms[0])
	msg.SetToRecipients(to)
	msg.SetCcRecipients(cc)
	msg.SetBccRecipients(bcc)
	msg.SetBody(graph.NewBody(M.Header.Get("Content-Type"), buf.String()))
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	msg, err = s.cl.CreateMessage(ctx, s.userID, s.folderID, msg)
	cancel()
	if err != nil {
		return nil, err
	}
	return &imap.AppendData{UIDValidity: s.idm.uidValidity, UID: s.idm.uidOf(s.folderID, *msg.GetId())}, nil
}

// Selected state
func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	destFolderID := *s.Folder(dest, true).GetId()
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	var sourceUIDs, destUIDs imap.UIDSet
	err := s.idm.forNumSet(ctx, s.folderID, numSet, true, nil, func(ctx context.Context, msgID string) error {
		msg, err := s.cl.MoveMessage(ctx, s.userID, s.folderID, msgID, destFolderID)
		if msg.GetId() != nil && *msg.GetId() != "" {
			sourceUIDs.AddNum(s.idm.uidOf(s.folderID, msgID))
			destUIDs.AddNum(s.idm.uidOf(destFolderID, *msg.GetId()))
		}
		return err
	})
	if err != nil {
		return err
	}
	return w.WriteCopyData(&imap.CopyData{
		UIDValidity: s.idm.uidValidity,
		SourceUIDs:  sourceUIDs,
		DestUIDs:    destUIDs,
	})
}

func (s *session) Unselect() error {
	s.folderID = ""
	//s.idm.Reset();
	return nil
}

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if uids == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	return s.idm.forNumSet(ctx, s.folderID, *uids, true,
		s.folderFetcher(s.folderID),
		func(ctx context.Context, msgID string) error {
			err := s.cl.DeleteMessage(ctx, s.userID, s.folderID, msgID)
			if wErr := w.WriteExpunge(uint32(s.idm.uidOf(
				s.folderID, msgID,
			))); wErr != nil && err == nil {
				err = wErr
			}
			return err
		})
}

func encodeCriteria(criteria imap.SearchCriteria, slctSorted []string) (filter, search string, slct []string) {
	F := func(t time.Time, end bool) string {
		t = t.Truncate(24 * time.Hour)
		if end {
			t = t.Add(24*time.Hour - time.Second)
		}
		return t.Format(time.RFC3339)
	}

	var filt, srch []string
	// slog.Info("encodeCriteria", "slct", slct, "slctSorted", slctSorted)
	slct = slctSorted
	need := func(s string) string {
		// old := slct
		slct = insert(slct, s)
		// slog.Info("need", "s", s, "old", old, "new", slct)
		return s
	}
	for _, f := range criteria.Flag {
		switch f {
		case imap.FlagSeen:
			filt = append(filt, need("isRead"))
		case imap.FlagFlagged:
			filt = append(filt, need("flag")+".flagStatus eq flagged")
		case imap.FlagImportant:
			filt = append(filt, need("importance")+" eq high")
		}
	}
	if !criteria.Since.IsZero() {
		filt = append(filt, need("received")+" ge "+F(criteria.Since, false))
	}
	if !criteria.Before.IsZero() {
		filt = append(filt, need("received")+" le "+F(criteria.Before, true))
	}
	if !criteria.SentSince.IsZero() {
		filt = append(filt, need("sent")+" ge "+F(criteria.SentSince, true))
	}
	if !criteria.SentBefore.IsZero() {
		filt = append(filt, need("sent")+" le "+F(criteria.SentBefore, true))
	}

	if criteria.Smaller != 0 {
		filt = append(filt, need("size")+fmt.Sprintf(" le %d", criteria.Smaller))
	}
	if criteria.Larger != 0 {
		filt = append(filt, need("size")+fmt.Sprintf(" ge %d", criteria.Larger))
	}

	for _, s := range criteria.Body {
		need("body")
		// srch = append(srch, need("body")+":"+graph.EscapeSingleQuote(s))
		srch = append(srch, graph.EscapeSingleQuote(s))
	}
	for _, s := range criteria.Text {
		need("subject")
		// srch = append(srch, need("subject")+":"+graph.EscapeSingleQuote(s))
		srch = append(srch, graph.EscapeSingleQuote(s))
	}
	for _, c := range criteria.Not {
		ff, ss, slsl := encodeCriteria(c, slct)
		slct = slsl
		filt = append(filt, "NOT ("+ff+")")
		srch = append(srch, "NOT ("+ss+")")
	}
	for _, cc := range criteria.Or {
		fa, sa, slsl := encodeCriteria(cc[0], slct)
		fb, sb, slsl := encodeCriteria(cc[1], slsl)
		slct = slsl
		filt = append(filt, "(("+fa+") OR ("+fb+"))")
		srch = append(srch, "(("+sa+") OR ("+sb+"))")
	}
	for _, h := range criteria.Header {
		if strings.EqualFold(h.Key, "subject") || strings.EqualFold(h.Key, "body") {
			need(cleanMailbox(h.Key))
			srch = append(srch, graph.EscapeSingleQuote(h.Value))
		} else {
			srch = append(srch, need(cleanMailbox(h.Key))+":"+graph.EscapeSingleQuote(h.Value))
		}
	}

	// TODO: other criteria values

	// slog.Info("encodeCriteria", "slct", slct)
	return strings.Join(filt, " AND "), strings.Join(srch, " AND "), slct
}

func insert[S ~[]E, E cmp.Ordered](x S, target E) S {
	if i, ok := slices.BinarySearch(x, target); !ok {
		return slices.Insert(x, i, target)
	}
	return x
}

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	qry := graph.Query{
		Select: []string{"id"},
	}
	if criteria != nil {
		qry.Filter, qry.Search, qry.Select = encodeCriteria(*criteria, qry.Select)
	}
	if len(qry.Search) == 0 {
		qry.Select = insert(qry.Select, "createdDateTime")
		qry.OrderBy = []string{"createdDateTime"}
	}

	logger := s.logger().With("qry", qry, "folderID", s.folderID, "folder", s.Folder(s.folderID, false).Mailbox)
	logger.Info("Search", "criteria", criteria, "qry", qry, "folder", s.folderID)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	msgs, err := s.cl.ListMessages(ctx, s.userID, s.folderID, qry)
	cancel()
	if err != nil {
		logger.Error("ListMessages", "qry", qry, "msgs", msgs, "error", err)
	} else {
		logger.Info("ListMessages", "qry", qry, "folder", s.folderID, "msgsNum", len(msgs))
	}
	var nums imap.UIDSet
	sd := imap.SearchData{Count: uint32(len(msgs))}
	for i, m := range msgs {
		uid := s.idm.uidOf(s.folderID, *m.GetId())
		if u := uint32(uid); i == 0 {
			sd.Min, sd.Max = u, u
		} else {
			if sd.Min > u {
				sd.Min = u
			}
			if sd.Max < u {
				sd.Max = u
			}
		}
		nums.AddNum(uid)
	}
	sd.All = nums
	logger.Debug("ListMessages", "sd", sd)
	return &sd, err
}

func (s *session) fetchFolder(ctx context.Context, folderID string) error {
	logger := s.logger()
	msgs, err := s.cl.ListMessages(ctx, s.userID, folderID, graph.Query{Select: []string{"id"}})
	for _, m := range msgs {
		if m.GetId() != nil && *m.GetId() != "" {
			_ = s.idm.uidOf(folderID, *m.GetId()) // cache it
		}
	}
	logger.Debug("fetchFolder", "folderID", folderID, "uids", len(msgs))
	return err
}
func (s *session) folderFetcher(folderID string) func(context.Context) error {
	return func(ctx context.Context) error { return s.fetchFolder(ctx, folderID) }
}

func (s *session) getCachedMIMEMessage(ctx context.Context, w io.Writer, msgID string) (filecache.ActionID, bool, error) {
	if s.p.cache == nil {
		return filecache.ActionID{}, false, nil
	}
	aID := filecache.NewActionID([]byte(msgID + "/GetMIMEMEssage"))
	logger := s.logger().With("msgID", msgID,
		"actionID", base64.URLEncoding.EncodeToString(aID[:]))
	cacheFn, _, err := s.p.cache.GetFile(aID)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "entry not found") {
			logger.Debug("cache.GetFile", "error", err)
			return aID, false, nil
		}
		logger.Warn("cache.GetFile", "error", err)
		return aID, false, err
	} else if fh, err := os.Open(cacheFn); err != nil {
		logger.Debug("cache.GetFile", "file", cacheFn, "error", err)
		return aID, false, nil
	} else {
		_, err = io.Copy(w, fh)
		fh.Close()
		if err != nil {
			logger.Error("read cache", "file", cacheFn, "error", err)
			os.Remove(fh.Name())
			return aID, false, err
		}
		return aID, true, nil
	}
}

func (s *session) getMIMEMessage(ctx context.Context, msgID string) ([]byte, error) {
	logger := s.logger().With("msgID", msgID)
	var buf bytes.Buffer
	aID, ok, err := s.getCachedMIMEMessage(ctx, &buf, msgID)
	if err != nil {
		logger.Warn("getCachedMIMEMessage", "error", err)
	} else if ok {
		return buf.Bytes(), nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buf.Reset()
	start := time.Now()
	b, err := s.cl.GetMIMEMessage(ctx, s.userID, msgID)
	dur := time.Since(start)
	if err != nil {
		logger.Error("GetMIMEMessage", "dur", dur.String(), "error", err)
		return nil, err
	}
	buf.Write(b)
	length := len(b)

	lvl := slog.LevelDebug
	if dur > time.Second {
		lvl = slog.LevelInfo
	}
	if logger.Enabled(ctx, lvl) {
		logger.Log(ctx, lvl,
			"GetMIMEMessage", "length", length, "dur", dur,
			"speedKiBs", float64(length>>10)/float64(dur/time.Second),
		)
	}
	if s.p.cache != nil {
		if _, _, err = s.p.cache.Put(aID, bytes.NewReader(buf.Bytes())); err != nil {
			logger.Warn("cache message", "error", err)
		}
	}

	return buf.Bytes(), nil
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.logger().Info("Fetch", "numSet", numSet, "numset", fmt.Sprintf("%#v", numSet), "folder", s.Folder(s.folderID, false).Mailbox, "options", options)
	ctx, cancel := context.WithTimeout(s.p.ctx, 15*time.Minute)
	defer cancel()

	qry := graph.Query{Select: []string{"flag", "isRead", "id", "importance", "internetMessageHeaders"}}
	return s.idm.forNumSet(ctx, s.folderID, numSet, true,
		s.folderFetcher(s.folderID),
		func(ctx context.Context, msgID string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			logger := s.logger().With("id", msgID)
			gm, err := s.cl.GetMessage(ctx, s.userID, msgID, qry)
			if err != nil {
				if errS := err.Error(); strings.Contains(errS, "NotFound") || strings.Contains(errS, "not found") {
					logger.Warn("not found", "msgID", msgID, "error", err)
					return nil
				}
				logger.Error("GetMessage", "msgID", msgID, "error", err)
				return err
			}
			logger.Debug("GetMessage", "messages", gm)

			msg := message{
				UID:    s.idm.uidOf(s.folderID, msgID),
				GetBuf: func() ([]byte, error) { return s.getMIMEMessage(ctx, msgID) },
				Flags:  make(map[imap.Flag]struct{}, 2),
			}
			for _, v := range gm.GetInternetMessageHeaders() {
				if v.GetName() != nil && v.GetValue() != nil {
					msg.Header.Add(*v.GetName(), *v.GetValue())
				}
			}
			if gm.GetFlag().GetFlagStatus().String() == "flagged" {
				msg.Flags[imap.FlagFlagged] = struct{}{}
			}
			if *gm.GetIsRead() {
				msg.Flags[imap.FlagSeen] = struct{}{}
			}
			mw := w.CreateMessage(uint32(msg.UID))
			if err := msg.fetch(mw, options); err != nil {
				mw.Close()
				return err
			}
			return nil
		})
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	s.logger().Info("Store", "numSet", numSet, "flags", flags)
	if flags == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	return s.idm.forNumSet(ctx, s.folderID, numSet, true, nil,
		func(ctx context.Context, msgID string) error {
			type updateFlags struct {
				Importance string `json:"importance"`
				Read       bool   `json:"isRead"`
			}
			upd := graph.NewMessage()
			var tbd bool
			for _, f := range flags.Flags {
				switch f {
				case imap.FlagSeen:
					t := true
					upd.SetIsRead(&t)
				case imap.FlagFlagged:
					upd.SetFlag(graph.NewFlag(true))
				case imap.FlagDeleted:
					tbd = true
				}
			}
			msg, err := s.cl.UpdateMessage(ctx, s.userID, msgID, upd)
			if err != nil {
				return err
			}
			if tbd {
				if err := s.cl.DeleteMessage(ctx, s.userID, s.folderID, msgID); err != nil {
					return err
				}
			}
			uid := s.idm.uidOf(s.folderID, *msg.GetId())
			mw := w.CreateMessage(uint32(uid))
			mw.WriteFlags(flags.Flags)
			mw.WriteUID(uid)
			return mw.Close()
		})
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	s.logger().Debug("Copy", "numSet", numSet, "dest", dest)
	destFolderID := *s.Folder(dest, true).GetId()
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	result := imap.CopyData{UIDValidity: s.idm.uidValidity}
	err := s.idm.forNumSet(ctx, s.folderID, numSet, true, nil,
		func(ctx context.Context, msgID string) error {
			msg, err := s.cl.CopyMessage(ctx, s.userID, s.folderID, msgID, destFolderID)
			if msg.GetId() != nil && *msg.GetId() != "" {
				result.SourceUIDs.AddNum(s.idm.uidOf(s.folderID, msgID))
				result.DestUIDs.AddNum(s.idm.uidOf(destFolderID, *msg.GetId()))
			}
			return err
		})
	return &result, err
}

func graphAddressList(it gomessage.HeaderFields) ([]graph.Recipient, error) {
	var rr []graph.Recipient
	for it.Next() {
		aa, err := mail.ParseAddressList(it.Value())
		if err != nil {
			return rr, err
		}
		for _, a := range aa {
			rr = append(rr, graph.NewRecipient(a.Name, a.Address))
		}
	}
	return rr, nil
}

// func printAddress(ee []graph.EmailAddress) string {
// 	var buf strings.Builder
// 	for _, a := range ee {
// 		if a.Name != "" {
// 			fmt.Fprintf(&buf, "%q <%s>", a.Name, a.Address)
// 		} else {
// 			fmt.Fprintf(&buf, "<%s>", a.Address)
// 		}
// 	}
// 	return buf.String()
// }
// func toAddresses(ee []graph.EmailAddress) []imap.Address {
// 	aa := make([]imap.Address, len(ee))
// 	for i, a := range ee {
// 		parts := strings.SplitN(a.Address, "@", 2)
// 		aa[i] = imap.Address{Name: a.Name, Mailbox: parts[0], Host: parts[1]}
// 	}
// 	return aa
// }

// func iterAddresses(ee gomessage.HeaderFields) []imap.Address {
// 	var aa []imap.Address
// 	for ee.Next() {
// 		addrs, err := mail.ParseAddressList(ee.Value())
// 		if err != nil {
// 			slog.Error("ParseAddressList", "text", ee.Value(), "error", err)
// 		}
// 		for _, a := range addrs {
// 			parts := strings.SplitN(a.Address, "@", 2)
// 			aa = append(aa, imap.Address{Name: a.Name, Mailbox: parts[0], Host: parts[1]})

// 		}
// 	}
// 	return aa
// }
