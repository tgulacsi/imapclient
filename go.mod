module github.com/tgulacsi/imapclient

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache v0.3.2
	github.com/AzureAD/microsoft-authentication-library-for-go v1.6.0
	github.com/UNO-SOFT/filecache v0.4.0
	github.com/UNO-SOFT/zlog v0.8.6
	github.com/dchest/siphash v1.2.3
	github.com/emersion/go-imap v1.2.1
	github.com/emersion/go-imap/v2 v2.0.0-beta.7
	github.com/emersion/go-message v0.18.2
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/hashicorp/go-azure-sdk v0.20240125.1100331
	github.com/microsoft/kiota-abstractions-go v1.9.3
	github.com/microsoftgraph/msgraph-sdk-go v1.89.0
	github.com/microsoftgraph/msgraph-sdk-go-core v1.4.0
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/tgulacsi/go v0.28.8-0.20251018153338-d2421125b113
	github.com/tgulacsi/oauth2client v0.1.0
	go.etcd.io/bbolt v1.4.0
	golang.org/x/exp v0.0.0-20251113190631-e25ba8c21ef6
	golang.org/x/net v0.47.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/sync v0.18.0
	golang.org/x/text v0.31.0
	golang.org/x/time v0.14.0
	gopkg.in/validator.v2 v2.0.1
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/AzureAD/microsoft-authentication-extensions-for-go/cache v0.1.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-linebreak v0.0.0-20180812204043-d8f37254e7d3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-azure-helpers v0.73.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/keybase/go-keychain v0.0.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/microsoft/kiota-authentication-azure-go v1.3.1 // indirect
	github.com/microsoft/kiota-http-go v1.5.4 // indirect
	github.com/microsoft/kiota-serialization-form-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-json-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-multipart-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-text-go v1.1.3 // indirect
	github.com/peterbourgon/ff/v4 v4.0.0-beta.1 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/std-uritemplate/std-uritemplate/go/v2 v2.0.8 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/term v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The last version supporting Xoauth2: github.com/emersion/go-sasl v0.0.0-20200509202850-4132e15e133d

go 1.24.1

// replace github.com/emersion/go-imap/v2 => ../../emersion/go-imap/v2

tool github.com/tgulacsi/go/openapi-generator-cli
