package graph

// https://aka.ms/get/kiota/latest/linux-x64.zip

//go:generate bash -c "test -s openapi.yaml || curl -sS -m30 -L https://aka.ms/graph/v1.0/openapi.yaml -o openapi.yaml"
//go:generate bash -c "test -s openapi.slim.yaml || go run ./graph_oas_reducer.go -in=openapi.yaml -out=openapi.slim.yaml"
//go:generate bash -c "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(nix eval --raw nixpkgs#icu)/lib; go tool openapi-generator-cli kiota generate --openapi openapi.slim.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /users/*/messages/** -i /me/mailFolders/** -i /users/*/mailFolders/** -i /me/messages/** -i /users/*/messages/** && go tool openapi-generator-cli kiota info -d openapi.slim.yaml -l Go"
// go : generate env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/nix/store/4fwry0vmvgii801mvcs5hqafi027xzyb-icu4c-77.1/lib go tool openapi-generator-cli kiota generate --openapi openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /users/*/messages/** -i /me/mailFolders/** -i /users/*/mailFolders/** -i /me/messages/** -i /users/*/messages/**
// go : generate go tool openapi-generator-cli kiota generate --openapi https://aka.ms/graph/v1.0/openapi.yaml --language Go -o msgraph -b --clean-output -n github.com/tgulacsi/imapclient/graph/msgraph -i /me -i /users -i /users/*/messages/* -i /me/mailFolders/* -i /users/*/mailFolders/*  -i /me/messages -i /users/*/messages
