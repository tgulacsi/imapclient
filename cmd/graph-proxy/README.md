# MSGraph-IMAP proxy
```
  go install github.com/tgulacsi/imapclient/cmd/graph-proxy@latest
  graph-proxy -client-id=xxx :1143
````

## Authentication, Authorization
Right now, this app uses *Application permission* with the OAuth 2.0 *credentials flow*.

Maybe a *Delegated permission* with the *implicit grant flow* would be better (though it must communicate with the user).

For description, see https://laurakokkarinen.com/how-to-set-up-an-azure-ad-application-registration-for-calling-microsoft-graph/ .

### OAuth 2.0 authorization code flow
https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow

### Azure CLI
https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt



