// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
	"github.com/tgulacsi/imapclient/graph"
)

func main() {
	if err := Main(); err != nil {
		slog.Error("Main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	var verbose zlog.VerboseVar
	logger := zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()
	flagClientID := flag.String("client-id", "", "ClientID")
	flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	flag.Var(&verbose, "v", "verbosity")
	flag.Parse()
	addr := flag.Arg(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	P := &proxy{ctx: ctx, tenantID: *flagTenantID, clientID: *flagClientID, Logger: logger}
	if *flagClientSecret != "" {
		if cl, users, err := P.connect(ctx, *flagTenantID, *flagClientID, *flagClientSecret); err != nil {
			return err
		} else {
			P.client, P.users = &cl, users
		}
	}

	var token struct{}
	opts := imapserver.Options{
		// NewSession is called when a client connects.
		NewSession: P.newSession,
		// Supported capabilities. If nil, only IMAP4rev1 is advertised. This set
		// must contain at least IMAP4rev1 or IMAP4rev2.
		//
		// the following capabilities are part of IMAP4rev2 and need to be
		// explicitly enabled by IMAP4rev1-only servers:
		//
		//   - NAMESPACE
		//   - UIDPLUS
		//   - ESEARCH
		//   - LIST-EXTENDED
		//   - LIST-STATUS
		//   - MOVE
		//   - STATUS=SIZE
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: token, //imap.CapIMAP4rev2: token,
			imap.CapNamespace: token, imap.CapUIDPlus: token,
			imap.CapESearch: token, //imap.CapListExtended: token,
			//imap.CapListStatus: token,
			//imap.CapMove: token, imap.CapStatusSize: token,
		},
		// Logger is a logger to print error messages. If nil, log.Default is used.
		Logger: slog.NewLogLogger(logger.With("imapserver").Handler(), slog.LevelError),
		// TLSConfig is a TLS configuration for STARTTLS. If nil, STARTTLS is
		// disabled.
		TLSConfig: nil,
		// InsecureAuth allows clients to authenticate without TLS. In this mode,
		// the server is susceptible to man-in-the-middle attacks.
		InsecureAuth: true,
	}
	if verbose > 1 {
		// Raw ingress and egress data will be written to this writer, if any.
		// Note, this may include sensitive information such as credentials used
		// during authentication.
		opts.DebugWriter = slogDebugWriter{logger}
	}
	srv := imapserver.New(&opts)

	if addr == "" {
		addr = ":143"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	return srv.Serve(ln)
}

const (
	delim  = '/'
	delimS = "/"
)

type Folder struct {
	graph.Folder
	Mailbox string
}

type proxy struct {
	ctx                context.Context
	client             *graph.GraphMailClient
	Logger             *slog.Logger
	users              []graph.User
	clientID, tenantID string
}

func (p *proxy) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	folders := make(map[string]*Folder)
	for k, vv := range graph.WellKnownFolders {
		folders[k] = &Folder{Folder: graph.Folder{WellKnownName: k, DisplayName: k}}
		for _, v := range vv {
			folders[v] = &Folder{Folder: graph.Folder{WellKnownName: k, DisplayName: v}}
		}
	}
	return &session{
			p: p, cl: p.client, users: p.users,
			conn: conn, idm: newUIDMap(),
			folders: folders,
		},
		&imapserver.GreetingData{PreAuth: false},
		nil
}

type session struct {
	p        *proxy
	cl       *graph.GraphMailClient
	users    []graph.User
	conn     *imapserver.Conn
	idm      *uidMap
	folders  map[string]*Folder
	folderID string
	userID   string
}

var _ imapserver.SessionIMAP4rev2 = (*session)(nil)

func (s *session) Close() error {
	conn := s.conn
	s.cl, s.conn, s.p = nil, nil, nil
	var firstErr error
	if conn == nil {
		return firstErr
	}
	if err := conn.Bye("QUIT"); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Not authenticated state

// Login with userID, clientSecret
func (s *session) Login(username, password string) error {
	logger := s.p.Logger.With("username", username, "password", password,
		"tenant", s.p.tenantID, "client", s.p.clientID)
	s.userID = ""
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	if s.cl == nil {
		cl, users, err := s.p.connect(ctx, s.p.tenantID, s.p.clientID, password)
		if err != nil {
			logger.Error("connect", "error", err)
			return fmt.Errorf("%w: %w", err, imapserver.ErrAuthFailed)
		}
		s.cl, s.users = &cl, users
	}
	for _, u := range s.users {
		if id := u.ID(); (id != nil && *id == username) ||
			(u.DisplayName != nil && strings.EqualFold(*u.DisplayName, username)) ||
			(u.EmployeeId != nil && string(*u.EmployeeId) == username) ||
			(u.Mail != nil && strings.EqualFold(string(*u.Mail), username)) ||
			(u.UserPrincipalName != nil && strings.EqualFold(string(*u.UserPrincipalName), username)) {
			s.userID = *id
		}
	}
	if s.userID == "" {
		logger.Error("user not found", "username", username, "users", s.users)
		return fmt.Errorf("user %q not found: %w", username, imapserver.ErrAuthFailed)
	}
	logger.Info("Login succeeded", "userID", s.userID)
	return nil
}

func (P proxy) connect(ctx context.Context, tenantID, clientID, clientSecret string) (graph.GraphMailClient, []graph.User, error) {
	logger := P.Logger.With("tenantID", tenantID, "clientID", clientID, "clientSecretLen", len(clientSecret))
	start := time.Now()
	cl, err := graph.NewGraphMailClient(ctx, tenantID, clientID, clientSecret)
	if err != nil {
		logger.Error("NewGraphMailClient", "dur", time.Since(start).String(), "error", err)
		return cl, nil, err
	}
	logger.Debug("NewGraphMailClient", "dur", time.Since(start).String())
	start = time.Now()
	users, err := cl.Users(ctx)
	if err != nil {
		logger.Error("Users", "dur", time.Since(start).String(), "error", err)
	} else {
		logger.Debug("Users", "dur", time.Since(start).String())
	}
	return cl, users, err
}

// Authenticated state
func (s *session) Namespace() (*imap.NamespaceData, error) {
	if s.cl == nil {
		return nil, imapserver.ErrAuthFailed
	}
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{
		{Prefix: "INBOX", Delim: delim},
	}}, nil
}

func (s *session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.p.Logger.Debug("Select", "mailbox", mailbox, "options", options)

	dirs := strings.Split(path.Clean(mailbox), delimS)
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	qry := graph.Query{Select: []string{
		"displayName", "ID", "parentFolderId", "wellKnownName",
		"totalItemCount", "unreadItemCount",
	}}
	folders, err := s.cl.ListMailFolders(ctx, s.userID, qry)
	if err != nil {
		return nil, err
	}
	var root graph.Folder
	dn, _ := path.Split(mailbox)
	if dn != "" {
		dn += delimS
	}
	for _, f := range folders {
		F := Folder{Folder: f, Mailbox: dn + f.DisplayName}
		s.folders[F.Mailbox] = &F
		s.folders[F.ID] = &F
		if root.ID == "" && (f.DisplayName == dirs[0] || strings.EqualFold(f.WellKnownName, dirs[0])) {
			root = f
		}
	}
	if root.ID == "" {
		return nil, fmt.Errorf("%q not found in %+v", dirs[0], folders)
	}
	for i, d := range dirs[1:] {
		if folders, err = s.cl.ListChildFolders(ctx, s.userID, root.ID, false, qry); err != nil {
			return nil, err
		}
		key := strings.Join(dirs[:i+1], delimS) + delimS
		var found bool
		for _, f := range folders {
			F := Folder{Folder: f, Mailbox: key + f.DisplayName}
			s.folders[key+f.DisplayName] = &F
			s.folders[f.ID] = &F
			if !found && (f.DisplayName == d || strings.EqualFold(f.WellKnownName, d)) {
				root, found = f, true
			}
		}
		if !found {
			return nil, fmt.Errorf("%q not found in %+v", d, folders)
		}
	}
	s.folderID = root.ID

	total := uint32(root.TotalItemCount)
	unread := uint32(root.UnreadItemCount)
	return &imap.SelectData{
		NumMessages: total,
		UIDValidity: s.idm.uidValidity, UIDNext: s.idm.uidNext(),
		List: &imap.ListData{
			Delim: delim, Mailbox: root.DisplayName,
			Status: &imap.StatusData{
				Mailbox:     root.DisplayName,
				NumMessages: &total,
				NumUnseen:   &unread,
				UIDNext:     s.idm.uidNext(), UIDValidity: s.idm.uidValidity,
			}},
	}, nil
}

func (s *session) Create(mailbox string, options *imap.CreateOptions) error {
	if s.folders[mailbox].ID != "" {
		return fmt.Errorf("%q already exist", mailbox)
	}
	dirs := strings.Split(path.Clean(mailbox), "/")
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	folder, err := s.cl.CreateFolder(ctx, s.userID, dirs[0])
	if err == nil {
		F := Folder{Folder: folder, Mailbox: dirs[0]}
		s.folders[dirs[0]] = &F
		s.folders[F.ID] = &F
		parent := folder
		for i, d := range dirs {
			if folder, err = s.cl.CreateChildFolder(ctx, s.userID, parent.ID, d); err != nil {
				return err
			}
			F := Folder{Folder: folder, Mailbox: strings.Join(dirs[:i+1], delimS)}
			s.folders[strings.Join(dirs[:i+1], delimS)] = &F
			s.folders[F.ID] = &F
			parent = folder
		}
	}
	if folder.ID != "" {
		F := Folder{Folder: folder, Mailbox: mailbox}
		s.folders[mailbox] = &F
		s.folders[F.ID] = &F
	}
	return err
}

func (s *session) Delete(mailbox string) error {
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	err := s.cl.DeleteFolder(ctx, s.userID, s.folders[mailbox].ID)
	if err != nil {
		err = s.cl.DeleteChildFolder(ctx, s.userID, s.folders[path.Dir(mailbox)].ID, s.folders[mailbox].ID)
	}
	cancel()
	return err
}

var ErrNotImplemented = errors.New("not implemented")

func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error    { return nil }
func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error { return nil }
func (s *session) Rename(mailbox, newName string) error                        { return ErrNotImplemented }
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
	s.p.Logger.Debug("List", "ref", ref, "patterns", patterns, "options", options)
	zero := imap.ListData{Delim: delim}
	data := zero
	ref = strings.Trim(ref, delimS)
	if ref == "" && len(patterns) == 0 {
		data.Mailbox = "INBOX"
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
		dirs := strings.Split(ref, delimS)
		for i, d := range dirs {
			if d == "" {
				continue
			}
			if folder := s.folders[d]; folder.ID == "" {
				qry := qry
				ed := graph.EscapeSingleQuote(d)
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
					return fmt.Errorf("no %q folder under %q", d, strings.Join(dirs[:i], delimS))
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
			} else if strings.EqualFold(f.DisplayName, "INBOX") {
				names[f.ParentFolderID] = ""
				names[f.ID] = f.DisplayName
			} else {
				rest++
			}
			// s.p.Logger.Debug("found", "displayName", f.DisplayName, "name", names[f.ID], "parentID", f.ParentFolderID)
		}
	}
	// s.p.Logger.Debug("found", "n", len(found), "m", len(names), "names", names)
	for _, f := range found {
		total := uint32(f.TotalItemCount)
		unread := uint32(f.UnreadItemCount)
		data = zero
		data.Mailbox = names[f.ID]
		data.Status = &imap.StatusData{
			Mailbox:     names[f.ID],
			NumMessages: &total,
			NumUnseen:   &unread,
			UIDNext:     s.idm.uidNext(),
			UIDValidity: s.idm.uidValidity,
		}
		s.p.Logger.Debug("list", "data", data)
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}

	return nil
}

func (s *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	s.p.Logger.Debug("Status", "mailbox", mailbox, "options", options)
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
		folders, err = s.cl.ListChildFolders(ctx, s.userID, s.folders[path.Dir(mailbox)].ID, false, qry)
	}
	cancel()
	if err != nil {
		s.p.Logger.Error("Select", "qry", qry, "error", err)
		return nil, err
	}
	for _, f := range folders {
		if !strings.EqualFold(f.DisplayName, bn) {
			continue
		}
		total := uint32(folders[0].TotalItemCount)
		unread := uint32(folders[0].UnreadItemCount)
		return &imap.StatusData{
			Mailbox:     mailbox,
			NumMessages: &total,
			NumUnseen:   &unread,
			UIDNext:     s.idm.uidNext(),
			// A good UIDVALIDITY value to use is a 32-bit representation of the current date/time when the value is assigned:
			UIDValidity: s.idm.uidValidity,
		}, err
	}
	return nil, fmt.Errorf("folder %q is not found under %q", bn, dn)
}

func (s *session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	M, err := message.Read(r)
	if err != nil {
		return nil, err
	}
	froms, err := parseAddressList(M.Header.Get("From"))
	if err != nil {
		return nil, err
	}
	to, _ := parseAddressList(M.Header.Get("To"))
	cc, _ := parseAddressList(M.Header.Get("Cc"))
	bcc, _ := parseAddressList(M.Header.Get("Bcc"))
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
	return &imap.AppendData{UIDValidity: s.idm.uidValidity, UID: s.idm.uidOf(msg.ID)}, nil
}

// Selected state
func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	destFolderID := s.folders[dest].ID
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	return forNumSet(numSet, true, func(msgID imap.UID) error {
		msg, err := s.cl.MoveMessage(ctx, s.userID, s.folderID, s.idm.idOf(msgID), destFolderID)
		if msg.ID != "" {
			_ = s.idm.uidOf(msg.ID)
		}
		return err
	})
}

func (s *session) Unselect() error { s.folderID = ""; s.idm.Reset(); return nil }

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if uids == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	return forNumSet(*uids, true, func(msgID imap.UID) error {
		err := s.cl.DeleteMessage(ctx, s.userID, s.folderID, s.idm.idOf(msgID))
		if wErr := w.WriteExpunge(uint32(msgID)); wErr != nil && err == nil {
			err = wErr
		}
		return err
	})
}

func encodeCriteria(criteria imap.SearchCriteria) (filter, search string) {
	F := func(t time.Time, end bool) string {
		t = t.Truncate(24 * time.Hour)
		if end {
			t = t.Add(24*time.Hour - time.Second)
		}
		return t.Format(time.RFC3339)
	}

	var filt, srch []string
	if !criteria.Since.IsZero() {
		filt = append(filt, "received ge "+F(criteria.Since, false))
	}
	if !criteria.Before.IsZero() {
		filt = append(filt, "received le "+F(criteria.Before, true))
	}
	if !criteria.SentSince.IsZero() {
		filt = append(filt, "sent ge "+F(criteria.SentSince, true))
	}
	if !criteria.SentBefore.IsZero() {
		filt = append(filt, "sent le "+F(criteria.SentBefore, true))
	}

	if criteria.Smaller != 0 {
		filt = append(filt, fmt.Sprintf("size le %d", criteria.Smaller))
	}
	if criteria.Larger != 0 {
		filt = append(filt, fmt.Sprintf("size ge %d", criteria.Larger))
	}

	for _, s := range criteria.Body {
		srch = append(srch, "body:"+graph.EscapeSingleQuote(s))
	}
	for _, s := range criteria.Text {
		srch = append(srch, "subject:"+graph.EscapeSingleQuote(s))
	}
	for _, c := range criteria.Not {
		ff, ss := encodeCriteria(c)
		filt = append(filt, "NOT ("+ff+")")
		srch = append(srch, "NOT ("+ss+")")
	}
	for _, cc := range criteria.Or {
		fa, sa := encodeCriteria(cc[0])
		fb, sb := encodeCriteria(cc[1])
		filt = append(filt, "(("+fa+") OR ("+fb+"))")
		srch = append(srch, "(("+sa+") OR ("+sb+"))")
	}
	for _, h := range criteria.Header {
		srch = append(srch, strings.ToLower(h.Key)+":"+graph.EscapeSingleQuote(h.Value))
	}

	// TODO: other criteria values

	return strings.Join(filt, " AND "), strings.Join(srch, " AND ")
}

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	qry := graph.Query{Select: []string{"id"}}
	if criteria != nil {
		qry.Filter, qry.Search = encodeCriteria(*criteria)
	}

	logger := s.p.Logger.With("qry", qry, "folderID", s.folderID, "folder", s.folders[s.folderID].DisplayName, "mbox", s.folders[s.folderID].Mailbox)
	logger.Debug("Search")
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	msgs, err := s.cl.ListMessages(ctx, s.userID, s.folderID, qry)
	cancel()
	logger.Debug("ListMessages", "qry", qry, "msgs", msgs, "error", err)
	var nums imap.UIDSet
	sd := imap.SearchData{UID: true, Count: uint32(len(msgs))}
	for i, m := range msgs {
		uid := s.idm.uidOf(m.ID)
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

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.p.Logger.Debug("Fetch", "numSet", numSet, "options", options)
	qry := graph.Query{}
	ctx, cancel := context.WithTimeout(s.p.ctx, 5*time.Minute)
	defer cancel()
	return forNumSet(numSet, true, func(msgID imap.UID) error {
		msgs, err := s.cl.GetMessage(ctx, s.userID, s.idm.idOf(msgID), qry)
		if err != nil {
			return err
		}
		for _, msg := range msgs {
			if err := func() error {
				mw := w.CreateMessage(uint32(msgID))
				defer mw.Close()
				if options.BodyStructure != nil {
					mt, params, _ := mime.ParseMediaType(msg.Body.ContentType)
					typ := strings.SplitN(mt, "/", 2)
					body := imap.BodyStructureSinglePart{
						Type: typ[0], Subtype: typ[1], Params: params, ID: msg.ID, Encoding: "utf8",
						Size: uint32(len(msg.Body.Content)),
						Text: &imap.BodyStructureText{NumLines: int64(strings.Count(msg.Body.Content, "\n"))},
					}
					mw.WriteBodyStructure(&body)
				}
				if options.Envelope {
					mw.WriteEnvelope(&imap.Envelope{
						Subject:   msg.Subject,
						From:      toAddresses([]graph.EmailAddress{msg.From}),
						To:        toAddresses(msg.To),
						Cc:        toAddresses(msg.Cc),
						Bcc:       toAddresses(msg.Bcc),
						Sender:    toAddresses([]graph.EmailAddress{msg.Sender}),
						MessageID: msg.ID,
					})
				}
				if options.UID {
					mw.WriteUID(s.idm.uidOf(msg.ID))
				}
				for _, bs := range options.BinarySection {
					if bs == nil {
						continue
					}
					size := int64(len(msg.Body.Content))
					cw := mw.WriteBinarySection(&imap.FetchItemBinarySection{Part: []int{0}, Partial: &imap.SectionPartial{Offset: 0, Size: size}}, size)
					io.WriteString(cw, msg.Body.Content)
					if err := cw.Close(); err != nil {
						return err
					}
					break
				}
				return mw.Close()
			}(); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	s.p.Logger.Debug("Store", "numSet", numSet, "flags", flags)
	if flags == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	return forNumSet(numSet, true, func(msgID imap.UID) error {
		type updateFlags struct {
			Read       bool   `json:"isRead"`
			Importance string `json:"importance"`
		}
		u := updateFlags{Importance: "normal"}
		var tbd bool
		for _, f := range flags.Flags {
			switch f {
			case "\\Seen":
				u.Read = true
			case "\\Flagged":
				u.Importance = "high"
			case "\\Deleted":
				tbd = true
			}
		}
		upd, err := json.Marshal(u)
		if err != nil {
			return err
		}
		msg, err := s.cl.UpdateMessage(ctx, s.userID, s.idm.idOf(msgID), json.RawMessage(upd))
		if err != nil {
			return err
		}
		if tbd {
			if err := s.cl.DeleteMessage(ctx, s.userID, s.folderID, s.idm.idOf(msgID)); err != nil {
				return err
			}
		}
		mw := w.CreateMessage(uint32(msgID))
		mw.WriteFlags(flags.Flags)
		mw.WriteUID(s.idm.uidOf(msg.ID))
		return mw.Close()
	})
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	s.p.Logger.Debug("Copy", "numSet", numSet, "dest", dest)
	destFolderID := s.folders[dest].ID
	ctx, cancel := context.WithTimeout(s.p.ctx, time.Minute)
	defer cancel()
	result := imap.CopyData{UIDValidity: s.idm.uidValidity}
	err := forNumSet(numSet, true, func(msgID imap.UID) error {
		msg, err := s.cl.CopyMessage(ctx, s.userID, s.folderID, s.idm.idOf(msgID), destFolderID)
		if msg.ID != "" {
			result.SourceUIDs.AddNum(msgID)
			result.DestUIDs.AddNum(s.idm.uidOf(msg.ID))
		}
		return err
	})
	return &result, err
}

type uidMap struct {
	mu          sync.RWMutex
	id2uid      map[string]imap.UID
	uid2id      map[imap.UID]string
	uidValidity uint32
}

func newUIDMap() *uidMap {
	m := &uidMap{id2uid: make(map[string]imap.UID), uid2id: make(map[imap.UID]string)}
	m.resetUidValidity()
	return m
}
func (m *uidMap) uidNext() imap.UID {
	m.mu.RLock()
	n := len(m.id2uid)
	m.mu.RUnlock()
	return imap.UID(n)
}

func (m *uidMap) idOf(uid imap.UID) string {
	m.mu.RLock()
	s := m.uid2id[uid]
	m.mu.RUnlock()
	return s
}

func (m *uidMap) Reset() {
	m.mu.Lock()
	clear(m.uid2id)
	clear(m.id2uid)
	m.resetUidValidity()
	m.mu.Unlock()
}
func (m *uidMap) resetUidValidity() {
	const epoch = 1725625771 // 2024-09-0614:29:31
	// A good UIDVALIDITY value to use is a 32-bit representation of the current date/time when the value is assigned:
	m.uidValidity = uint32(time.Now().Unix() - epoch)
}

func (m *uidMap) uidOf(s string) imap.UID {
	m.mu.RLock()
	uid, ok := m.id2uid[s]
	m.mu.RUnlock()
	if ok {
		return uid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if uid, ok = m.id2uid[s]; ok {
		return uid
	}
	uid = imap.UID(len(m.id2uid) + 1)
	m.id2uid[s] = uid
	m.uid2id[uid] = s
	return uid
}

func forNumSet(numSet imap.NumSet, full bool, f func(imap.UID) error) error {
	var firstErr error
	if ss, ok := numSet.(imap.SeqSet); ok {
		nums, _ := ss.Nums()
		for _, msgID := range nums {
			if err := f(imap.UID(msgID)); err != nil && firstErr == nil {
				if !full {
					return err
				}
				firstErr = err
			}
		}
	} else if us, ok := numSet.(imap.UIDSet); ok {
		for _, ur := range us {
			for msgID := ur.Start; msgID <= ur.Stop; msgID++ {
				if err := f(msgID); err != nil && firstErr == nil {
					if !full {
						return err
					}
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

func parseAddressList(s string) ([]graph.EmailAddress, error) {
	aa, err := mail.ParseAddressList(s)
	rr := make([]graph.EmailAddress, 0, len(aa))
	for _, a := range aa {
		rr = append(rr, graph.EmailAddress{Name: a.Name, Address: a.Address})
	}
	return rr, err
}

func printAddress(ee []graph.EmailAddress) string {
	var buf strings.Builder
	for _, a := range ee {
		if a.Name != "" {
			fmt.Fprintf(&buf, "%q <%s>", a.Name, a.Address)
		} else {
			fmt.Fprintf(&buf, "<%s>", a.Address)
		}
	}
	return buf.String()
}
func toAddresses(ee []graph.EmailAddress) []imap.Address {
	aa := make([]imap.Address, len(ee))
	for i, a := range ee {
		parts := strings.SplitN(a.Address, "@", 2)
		aa[i] = imap.Address{Name: a.Name, Mailbox: parts[0], Host: parts[1]}
	}
	return aa
}

type slogDebugWriter struct{ *slog.Logger }

func (s slogDebugWriter) Write(p []byte) (int, error) {
	s.Logger.Debug(string(p))
	return len(p), nil
}
