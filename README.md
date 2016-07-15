# imapclient
imapclient is a helper library for speaking with IMAP4rev1 servers:
list and select mailboxes, search for mails and download them.

# imapdump
./cmd/imapdump is a usable example program for listing mailboxes and downloading mail in tar format.

## Install

	go get github.com/tgulacsi/imapclient/cmd/imapdump

## Usage

    imapdump -H imap.gmail.com -p 993 -U myloginname -P mysecretpassword tree %

will list all mailboxes

    imapdump -H imap.gmail.com -p 993 -U myloginname -P mysecretpassword list -a Trash

will list the contents (UID, size and subject) of the Trash folder, even seen mails,

    imapdump -H imap.gmail.com -p 993 -U myloginname -P mysecretpassword save -m Trash 3602

will dump the message from Trash folder with UID of 3602,

    imapdump -H imap.gmail.com -p 993 -U myloginname -P mysecretpassword save -m Trash -o trash.tar

will save all the mails under Trash into trash.tar.

