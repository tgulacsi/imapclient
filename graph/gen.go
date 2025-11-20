package graph

// https://aka.ms/get/kiota/latest/linux-x64.zip

// Does not help, the generated code won't be smaller...
//
//go:generate go tool openapi-generator-cli kiota generate --openapi openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /me -i /users -i /users/*/messages/* -i /me/mailFolders/* -i /users/*/mailFolders/*  -i /me/messages -i /users/*/messages
// go : generate go tool openapi-generator-cli kiota generate --openapi https://aka.ms/graph/v1.0/openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /me -i /users -i /users/*/messages/* -i /me/mailFolders/* -i /users/*/mailFolders/*  -i /me/messages -i /users/*/messages
