// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/mail"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	"github.com/tgulacsi/imapclient/graph"
	"golang.org/x/exp/maps"
)

func (p *proxy) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	folders := make(map[string]*Folder)
	for k, vv := range graph.WellKnownFolders {
		folders[cleanMailbox(k)] = &Folder{Folder: graph.Folder{WellKnownName: k, DisplayName: k}}
		for _, v := range vv {
			folders[cleanMailbox(v)] = &Folder{Folder: graph.Folder{WellKnownName: k, DisplayName: v}}
		}
	}
	return &session{
			p:    p,
			conn: conn, idm: newUIDMap(),
			folders: folders,
		},
		&imapserver.GreetingData{PreAuth: false},
		nil
}

type session struct {
	cl            graph.GraphMailClient
	p             *proxy
	conn          *imapserver.Conn
	idm           *uidMap
	folders       map[string]*Folder
	folderID      string
	userID        string
	mboxDeltaLink string
	users         []graph.User
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
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	var err error
	if s.cl, s.users, err = s.p.connect(ctx, tenantID, clientSecret); err != nil {
		logger.Error("connect", "error", err)
		return fmt.Errorf("%w: %w", err, imapserver.ErrAuthFailed)
	}
	for _, u := range s.users {
		if id := u.ID(); (id != nil && *id == user) ||
			(u.DisplayName != nil && strings.EqualFold(*u.DisplayName, user)) ||
			(u.EmployeeId != nil && string(*u.EmployeeId) == user) ||
			(u.Mail != nil && strings.EqualFold(string(*u.Mail), user)) ||
			(u.UserPrincipalName != nil && strings.EqualFold(string(*u.UserPrincipalName), user)) {
			s.userID = *id
		}
	}
	if s.userID == "" {
		logger.Error("user not found", "user", user, "users", s.users)
		if len(s.users) != 1 {
			return fmt.Errorf("user %q not found: %w", user, imapserver.ErrAuthFailed)
		}
		s.userID = *s.users[0].ID()
	}
	logger.Info("Login succeeded", "userID", s.userID)
	start := time.Now()
	err = s.fetchMailboxes(ctx, nil, false)
	logger.Info("fetchMailboxes", "dur", time.Since(start).String(), "count", len(s.folders))
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
	if len(s) == 36 && strings.Count(s, "-") == 4 && strings.IndexFunc(s, func(r rune) bool { return !('0' <= r && r <= '9' || r == '-' || 'a' <= r && r <= 'f') }) < 0 {
		return s
	}
	return strings.ToLower(strings.Trim(s, delimS))
}
func (s *session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	logger := s.logger().With("mailbox", mailbox)
	logger.Info("Select", "options", options)

	dn, _ := path.Split(mailbox)
	if dn != "" {
		dn += delimS
	}
	dirs := strings.Split(path.Clean(mailbox), delimS)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	key := cleanMailbox(mailbox)
	root := s.folders[key]
	if root == nil || root.ID == "" || root.TotalItemCount == 0 {
		if err := s.fetchMailboxes(ctx, dirs, true); err != nil {
			return nil, err
		}
		root = s.folders[key]
	}
	s.folderID, s.mboxDeltaLink = root.ID, ""

	total := uint32(root.TotalItemCount)
	unread := uint32(root.UnreadItemCount)
	uidNext := s.idm.uidNext(root.ID)
	return &imap.SelectData{
		NumMessages: total,
		UIDValidity: s.idm.uidValidity, UIDNext: uidNext,
		List: &imap.ListData{
			Delim: delim, Mailbox: root.DisplayName,
			Status: &imap.StatusData{
				Mailbox:     root.DisplayName,
				NumMessages: &total,
				NumUnseen:   &unread,
				UIDNext:     uidNext, UIDValidity: s.idm.uidValidity,
			}},
	}, nil
}

func (s *session) fetchMailboxes(ctx context.Context, dirs []string, count bool) error {
	slcts := []string{
		"displayName", "ID", "parentFolderId", "wellKnownName",
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
		folders, err := s.cl.ListChildFolders(ctx, s.userID, parent.ID, false, qry)
		if err != nil {
			return err
		} else if len(folders) == 0 {
			return nil
		}
		key := cleanMailbox(parent.Mailbox) + delimS
		for _, f := range folders {
			f.ParentFolderID = parent.ID
			F := Folder{Folder: f, Mailbox: key + f.DisplayName}
			s.folders[key+cleanMailbox(f.DisplayName)] = &F
			s.folders[f.ID] = &F

			if len(dirs) == 0 ||
				(strings.EqualFold(f.DisplayName, dirs[0]) ||
					strings.EqualFold(f.WellKnownName, dirs[0])) && len(dirs) > 1 {
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
		F := Folder{Folder: f, Mailbox: f.DisplayName}
		s.folders[cleanMailbox(F.Mailbox)] = &F
		s.folders[F.ID] = &F
		if len(dirs) == 0 ||
			f.DisplayName == dirs[0] || strings.EqualFold(f.WellKnownName, dirs[0]) {
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
	if s.folders[cleanMailbox(mailbox)] != nil {
		logger.Warn("already exist")
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	dirs := strings.Split(path.Clean(mailbox), "/")
	var parent graph.Folder
	for i := range dirs {
		dir := cleanMailbox(strings.Join(dirs[:i+1], delimS))
		if F := s.folders[dir]; F != nil && F.ID != "" {
			parent = F.Folder
			continue
		}
		if i == 0 {
			folder, err := s.cl.CreateFolder(ctx, s.userID, dirs[0])
			if err == nil {
				F := Folder{Folder: folder, Mailbox: dirs[0]}
				s.folders[dir] = &F
				s.folders[F.ID] = &F
			} else if strings.Contains(err.Error(), "ErrorFolderExists") {
				// folder = s.folders[dir].Folder
				logger.Error("ERR already exist", "dir", dirs[:i+1], "id", folder.ID, "have", maps.Keys(s.folders))
				return s.fetchMailboxes(ctx, nil, false)
			} else {
				return err
			}
			parent = folder
			continue
		}
		if parent.ID == "" {
			return fmt.Errorf("nil parent for %q; have: %q", dirs[:i+1], maps.Keys(s.folders))
		}
		folder, err := s.cl.CreateChildFolder(
			ctx, s.userID, parent.ID, dirs[i],
		)
		if err == nil {
			F := Folder{Folder: folder, Mailbox: strings.Join(dirs[:i+1], delimS)}
			s.folders[dir] = &F
			s.folders[F.ID] = &F
		} else if strings.Contains(err.Error(), "ErrorFolderExists") {
			logger.Warn("already exists", "dir", dir)
			folder = s.folders[dir].Folder
		} else {
			return err
		}
		parent = folder
	}
	return nil
}

func (s *session) Delete(mailbox string) error {
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	err := s.cl.DeleteFolder(ctx, s.userID, s.folders[cleanMailbox(mailbox)].ID)
	if err != nil {
		err = s.cl.DeleteChildFolder(ctx, s.userID, s.folders[path.Dir(cleanMailbox(mailbox))].ID, s.folders[cleanMailbox(mailbox)].ID)
	}
	cancel()
	return err
}

var ErrNotImplemented = errors.New("not implemented")

func (s *session) Rename(mailbox, newName string) error {
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	err := s.cl.RenameFolder(ctx, s.userID, s.folders[cleanMailbox(mailbox)].ID, newName)
	cancel()
	return err
}

func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	logger := s.logger()
	logger.Info("Poll", "allowExpunge", allowExpunge)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	if s.folderID == "" {
		logger.Warn("POLL before SELECT")
		return nil
	}
	f := s.folders[s.folderID]
	if f == nil {
		if err := s.fetchMailboxes(ctx, nil, false); err != nil {
			return err
		}
		if f = s.folders[s.folderID]; f == nil {
			return fmt.Errorf("folderID %q not found", s.folderID)
		}
	}
	changes, deltaLink, err := s.cl.DeltaMails(s.p.ctx, s.userID, f.ID, s.mboxDeltaLink)
	if err != nil {
		return err
	}
	if deltaLink != "" {
		s.mboxDeltaLink = deltaLink
	}
	var flags []imap.Flag
	for _, c := range changes {
		flags = flags[:0]
		if c.Removed != nil {
			flags = append(flags, imap.FlagDeleted)
		}
		if c.Read {
			flags = append(flags, imap.FlagSeen)
		}
		uid := s.idm.uidOf(f.ID, c.ID)
		if err := w.WriteMessageFlags(uint32(uid), uid, flags); err != nil {
			return err
		}
	}
	return nil
}

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
		"displayName", "Id", "wellKnownName", "parentFolderId",
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
				if imapserver.MatchList(f.DisplayName, delim, ref, pat) {
					found = append(found, f)
				}
			}
		}
	} else {
		dirs := strings.Split(cleanMailbox(ref), delimS)
		for i := range dirs {
			dir := strings.Join(dirs[:i+1], delimS)
			if folder := s.folders[dir]; folder.ID == "" {
				qry := qry
				ed := graph.EscapeSingleQuote(dirs[i])
				qry.Filter = "displayName:" + ed + " OR wellKnownName:" + ed
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
				parentID = folders[0].ID
			}
		}
		folders, err := s.cl.ListChildFolders(ctx, s.userID, parentID, false, qry)
		if err != nil {
			return err
		}
		for _, f := range folders {
			for _, pat := range patterns {
				if name := ref + delimS + f.DisplayName; imapserver.MatchList(name, delim, ref, pat) {
					found = append(found, f)
				}
			}
		}
	}

	names := make(map[string]string)
	rest := len(found)
	for rest > 0 {
		rest = 0
		for _, f := range found {
			if names[f.ID] != "" {
				continue
			} else if f.ParentFolderID == "" {
				names[f.ID] = f.DisplayName
			} else if parent, ok := names[f.ParentFolderID]; ok {
				if parent == "" {
					names[f.ID] = f.DisplayName
				} else {
					names[f.ID] = parent + delimS + f.DisplayName
				}
			} else if strings.EqualFold(f.DisplayName, "Inbox") {
				names[f.ParentFolderID] = ""
				names[f.ID] = f.DisplayName
			} else {
				rest++
			}
			logger.Debug("found", "displayName", f.DisplayName, "name", names[f.ID], "parentID", f.ParentFolderID)
		}
	}
	// s.logger().Debug("found", "n", len(found), "m", len(names), "names", names)
	for _, f := range found {
		total := uint32(f.TotalItemCount)
		unread := uint32(f.UnreadItemCount)
		data = zero
		data.Mailbox = names[f.ID]
		data.Status = &imap.StatusData{
			Mailbox:     names[f.ID],
			NumMessages: &total,
			NumUnseen:   &unread,
			UIDNext:     s.idm.uidNext(f.ID),
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
		folders, err = s.cl.ListChildFolders(ctx, s.userID, s.folders[path.Dir(cleanMailbox(mailbox))].ID, false, qry)
	}
	cancel()
	if err != nil {
		logger.Error("Select", "qry", qry, "error", err)
		return nil, err
	}
	for _, f := range folders {
		if !strings.EqualFold(f.DisplayName, bn) {
			logger.Debug("skip", "folder", f.DisplayName)
			continue
		}
		total := uint32(folders[0].TotalItemCount)
		unread := uint32(folders[0].UnreadItemCount)
		return &imap.StatusData{
			Mailbox:     mailbox,
			NumMessages: &total,
			NumUnseen:   &unread,
			UIDNext:     s.idm.uidNext(f.ID),
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
	msg := graph.Message{
		Subject: M.Header.Get("Subject"),
		From:    froms[0], To: to, Cc: cc, Bcc: bcc,
		Body: graph.Content{ContentType: M.Header.Get("Content-Type"), Content: buf.String()},
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	msg, err = s.cl.CreateMessage(ctx, s.userID, s.folderID, msg)
	cancel()
	if err != nil {
		return nil, err
	}
	return &imap.AppendData{UIDValidity: s.idm.uidValidity, UID: s.idm.uidOf(s.folderID, msg.ID)}, nil
}

// Selected state
func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	destFolderID := s.folders[cleanMailbox(dest)].ID
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	var sourceUIDs, destUIDs imap.UIDSet
	err := s.idm.forNumSet(ctx, s.folderID, numSet, true, nil, func(msgID string) error {
		msg, err := s.cl.MoveMessage(ctx, s.userID, s.folderID, msgID, destFolderID)
		if msg.ID != "" {
			sourceUIDs.AddNum(s.idm.uidOf(s.folderID, msgID))
			destUIDs.AddNum(s.idm.uidOf(destFolderID, msg.ID))
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

func (s *session) Unselect() error { s.folderID = ""; s.idm.Reset(); return nil }

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if uids == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	return s.idm.forNumSet(ctx, s.folderID, *uids, true,
		s.fetcherFor(ctx, s.folderID),
		func(msgID string) error {
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
		qry.OrderBy = graph.OrderBy{Field: "createdDateTime", Direction: graph.Ascending}
	}

	logger := s.logger().With("qry", qry, "folderID", s.folderID, "folder", s.folders[s.folderID].Mailbox)
	logger.Info("Search", "criteria", criteria, "qry", qry)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	msgs, err := s.cl.ListMessages(ctx, s.userID, s.folderID, qry)
	cancel()
	if err != nil {
		logger.Error("ListMessages", "qry", qry, "msgs", msgs, "error", err)
	} else {
		logger.Info("ListMessages", "qry", qry, "msgsNum", len(msgs))
	}
	var nums imap.UIDSet
	sd := imap.SearchData{UID: true, Count: uint32(len(msgs))}
	for i, m := range msgs {
		uid := s.idm.uidOf(s.folderID, m.ID)
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

func (s *session) fetcherFor(ctx context.Context, folderID string) func() ([]string, error) {
	return func() ([]string, error) {
		logger := s.logger()
		msgs, err := s.cl.ListMessages(ctx, s.userID, folderID, graph.Query{Select: []string{"id"}})
		ids := make([]string, 0, len(msgs))
		for _, m := range msgs {
			if m.ID != "" {
				_ = s.idm.uidOf(folderID, m.ID) // cache it
				ids = append(ids, m.ID)
			}
		}
		logger.Info("fetch", "folderID", folderID, "uids", len(ids))
		return ids, err
	}
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.logger().Info("Fetch", "numSet", numSet, "numset", fmt.Sprintf("%#v", numSet), "folder", s.folders[s.folderID].Mailbox, "options", options)
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()

	qry := graph.Query{Select: []string{"flag", "isRead", "id", "importance"}}
	var buf bytes.Buffer
	return s.idm.forNumSet(ctx, s.folderID, numSet, true,
		s.fetcherFor(ctx, s.folderID),
		func(msgID string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			logger := s.logger().With("id", msgID)
			type gmErr struct {
				Message graph.Message
				Err     error
			}
			mCh := make(chan gmErr, 1)
			go func() {
				gm, err := s.cl.GetMessage(ctx, s.userID, msgID, qry)
				mCh <- gmErr{Message: gm, Err: err}
			}()
			buf.Reset()
			length, err := s.cl.GetMIMEMessage(ctx, &buf, s.userID, msgID)
			if err != nil {
				logger.Error("GetMIMEMessage", "error", err)
				return err
			}

			logger.Debug("GetMIMEMessage", "id", msgID, "length", length)
			msg := message{uid: s.idm.uidOf(s.folderID, msgID), buf: buf.Bytes(), flags: make(map[imap.Flag]struct{}, 2)}
			gm := <-mCh
			if gm.Err != nil {
				logger.Error("getMessage", "error", gm.Err)
				return gm.Err
			}
			logger.Debug("GetMessage", "messages", gm)
			if gm.Message.Flag.Status == "flagged" {
				msg.flags[imap.FlagFlagged] = struct{}{}
			}
			if gm.Message.Read {
				msg.flags[imap.FlagSeen] = struct{}{}
			}
			mw := w.CreateMessage(uint32(msg.uid))
			if err := msg.fetch(mw, options); err != nil {
				mw.Close()
				return err
			}
			return nil
		})
}

var errWrongUID = errors.New("wrong UID")

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	s.logger().Info("Store", "numSet", numSet, "flags", flags)
	if flags == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	return s.idm.forNumSet(ctx, s.folderID, numSet, true, nil,
		func(msgID string) error {
			type updateFlags struct {
				Importance string `json:"importance"`
				Read       bool   `json:"isRead"`
			}
			u := updateFlags{Importance: "normal"}
			var tbd bool
			for _, f := range flags.Flags {
				switch f {
				case imap.FlagSeen:
					u.Read = true
				case imap.FlagFlagged:
					u.Importance = "high"
				case imap.FlagDeleted:
					tbd = true
				}
			}
			upd, err := json.Marshal(u)
			if err != nil {
				return err
			}
			msg, err := s.cl.UpdateMessage(ctx, s.userID, msgID, json.RawMessage(upd))
			if err != nil {
				return err
			}
			if tbd {
				if err := s.cl.DeleteMessage(ctx, s.userID, s.folderID, msgID); err != nil {
					return err
				}
			}
			uid := s.idm.uidOf(s.folderID, msg.ID)
			mw := w.CreateMessage(uint32(uid))
			mw.WriteFlags(flags.Flags)
			mw.WriteUID(uid)
			return mw.Close()
		})
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	s.logger().Debug("Copy", "numSet", numSet, "dest", dest)
	destFolderID := s.folders[cleanMailbox(dest)].ID
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	result := imap.CopyData{UIDValidity: s.idm.uidValidity}
	err := s.idm.forNumSet(ctx, s.folderID, numSet, true, nil, func(msgID string) error {
		msg, err := s.cl.CopyMessage(ctx, s.userID, s.folderID, msgID, destFolderID)
		if msg.ID != "" {
			result.SourceUIDs.AddNum(s.idm.uidOf(s.folderID, msgID))
			result.DestUIDs.AddNum(s.idm.uidOf(destFolderID, msg.ID))
		}
		return err
	})
	return &result, err
}

// uidMap is a per-folder UID->msgID map
//
// The other way (msgID->UID) is the fnv1 hash of the msgID.
// So the UIDs won't change, but may collide - that's why
// we use a per-folder map, to minimize this risk.
type uidMap struct {
	uid2id      map[string]map[imap.UID]string
	mu          sync.RWMutex
	uidValidity uint32
}

func newUIDMap() *uidMap {
	m := &uidMap{uid2id: make(map[string]map[imap.UID]string)}
	m.resetUidValidity()
	return m
}
func (m *uidMap) uidNext(folderID string) imap.UID {
	m.mu.RLock()
	n := len(m.uid2id[folderID])
	m.mu.RUnlock()
	return imap.UID(n)
}

func (m *uidMap) idOf(folderID string, uid imap.UID) string {
	m.mu.RLock()
	if m.uid2id[folderID] == nil {
		panic("no folderID=" + folderID + "seen yet")
	}
	s := m.uid2id[folderID][uid]
	m.mu.RUnlock()
	return s
}

func (m *uidMap) Reset() {
	m.mu.Lock()
	clear(m.uid2id)
	m.resetUidValidity()
	m.mu.Unlock()
}
func (m *uidMap) resetUidValidity() {
	const epoch = 1725625771 // 2024-09-0614:29:31
	// A good UIDVALIDITY value to use is a 32-bit representation of the current date/time when the value is assigned:
	// m.uidValidity = uint32(time.Now().Unix() - epoch)
	m.uidValidity = 0
}

func (m *uidMap) uidOf(folderID, msgID string) imap.UID {
	hsh := fnv.New32()
	hsh.Write([]byte(msgID))
	uid := imap.UID(hsh.Sum32())
	m.mu.RLock()
	_, ok := m.uid2id[folderID][uid]
	m.mu.RUnlock()
	if ok {
		return uid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok = m.uid2id[folderID][uid]; ok {
		return uid
	}
	if m.uid2id[folderID] == nil {
		m.uid2id[folderID] = make(map[imap.UID]string)
	}
	m.uid2id[folderID][uid] = msgID
	return uid
}

func isDynamic(numSet imap.NumSet) bool {
	if ss, ok := numSet.(imap.SeqSet); ok {
		return ss.Dynamic()
	} else if us, ok := numSet.(imap.UIDSet); ok {
		return us.Dynamic()
	}
	return false
}

func (m *uidMap) forNumSet(ctx context.Context, folderID string, numSet imap.NumSet, full bool, fetch func() ([]string, error), f func(string) error) error {
	var firstErr error
	var next func() (string, bool)
	var dyn bool
	if ss, ok := numSet.(imap.SeqSet); ok {
		if dyn = ss.Dynamic(); !dyn {
			nums, _ := ss.Nums()
			next = func() (string, bool) {
				for len(nums) != 0 {
					n := nums[0]
					nums = nums[1:]
					if id := m.idOf(folderID, imap.UID(n)); id != "" {
						return id, len(nums) != 0
					}
				}
				return "", false
			}
		}
	} else if us, ok := numSet.(imap.UIDSet); ok {
		if dyn = us.Dynamic(); !dyn {
			ur := us[0]
			us = us[1:]
			first := true
			var msgID imap.UID
			next = func() (string, bool) {
				cont := true
				for cont {
					if first {
						msgID = ur.Start
						first = false
					} else if msgID >= ur.Stop {
						if len(us) == 0 {
							cont = false
						} else {
							ur = us[0]
							us = us[1:]
							first = true
						}
					} else {
						msgID++
					}
					if id := m.idOf(folderID, msgID); id != "" {
						return id, cont
					}
				}
				return "", false
			}
		}
	}

	m.mu.RLock()
	folderUnknown := m.uid2id[folderID] == nil
	m.mu.RUnlock()
	fetched := fetch == nil
	if !fetched && (dyn || folderUnknown) {
		if ids, err := fetch(); err != nil {
			return err
		} else {
			fetched = true
			next = func() (string, bool) {
				id := ids[0]
				ids = ids[1:]
				return id, len(ids) != 0
			}
		}
	}

	for id, cont := next(); cont; id, cont = next() {
		if id == "" {
			continue
		}
		if err := f(id); err != nil && firstErr == nil {
			if !full {
				return err
			}
			firstErr = err
		}
	}

	return firstErr
}

func graphAddressList(it gomessage.HeaderFields) ([]graph.EmailAddress, error) {
	var rr []graph.EmailAddress
	for it.Next() {
		aa, err := mail.ParseAddressList(it.Value())
		if err != nil {
			return rr, err
		}
		for _, a := range aa {
			rr = append(rr, graph.EmailAddress{Name: a.Name, Address: a.Address})
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
