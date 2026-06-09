package graph

// https://aka.ms/get/kiota/latest/linux-x64.zip

// Does not help, the generated code won't be smaller...
//
// go : generate curl -L https://aka.ms/graph/v1.0/openapi.yaml -o openapi.yaml
//go:generate bash -c "env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(nix eval --raw nixpkgs#icu)/lib go tool openapi-generator-cli kiota generate --openapi openapi.yaml --language Go -o msgraph --clean-output --clear-cache --namespace-name 'github.com/tgulacsi/imapclient/graph/msgraph' --include-path '/me/mailFolders' --include-path '/me/mailFolders/**' --include-path '/me/messages' --include-path '/me/messages/**' --include-path '/users/*/mailFolders' --include-path '/users/*/mailFolders/**' --include-path '/users/*/messages' --include-path '/users/*/messages/**'"
// go : generate go tool openapi-generator-cli kiota generate --openapi https://aka.ms/graph/v1.0/openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /me -i /users -i /users/*/messages/* -i /me/mailFolders/* -i /users/*/mailFolders/*  -i /me/messages -i /users/*/messages
