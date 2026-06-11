package graph

// https://aka.ms/get/kiota/latest/linux-x64.zip

// Does not help, the generated code won't be smaller...
//
// go : generate curl -L https://aka.ms/graph/v1.0/openapi.yaml -o openapi.yaml
<<<<<<< Updated upstream
//go:generate bash -c "env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(nix eval --raw nixpkgs#icu)/lib go tool openapi-generator-cli kiota generate --openapi openapi.yaml --language Go -o msgraph --clean-output --clear-cache --namespace-name 'github.com/tgulacsi/imapclient/graph/msgraph' --include-path '/me/mailFolders' --include-path '/me/mailFolders/**' --include-path '/me/messages' --include-path '/me/messages/**' --include-path '/users/*/mailFolders' --include-path '/users/*/mailFolders/**' --include-path '/users/*/messages' --include-path '/users/*/messages/**'"
=======
// go : generate go run ./graph_oas_reducer.go -in=openapi.yaml -out=openapi.slim.yaml
//go:generate bash -c "env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(nix eval --raw nixpkgs#icu)/lib go tool openapi-generator-cli kiota generate --openapi openapi.slim.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /users/*/messages/** -i /me/mailFolders/** -i /users/*/mailFolders/** -i /me/messages/** -i /users/*/messages/**"
// go : generate env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/nix/store/4fwry0vmvgii801mvcs5hqafi027xzyb-icu4c-77.1/lib go tool openapi-generator-cli kiota generate --openapi openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /users/*/messages/** -i /me/mailFolders/** -i /users/*/mailFolders/** -i /me/messages/** -i /users/*/messages/**
>>>>>>> Stashed changes
// go : generate go tool openapi-generator-cli kiota generate --openapi https://aka.ms/graph/v1.0/openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /me -i /users -i /users/*/messages/* -i /me/mailFolders/* -i /users/*/mailFolders/*  -i /me/messages -i /users/*/messages
