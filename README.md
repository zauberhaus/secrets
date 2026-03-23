# secrets

A Go library for handling sensitive values (passwords, tokens, API keys, …) safely.
Secrets are never exposed through `String()`, JSON marshaling, or flag help text — only through an explicit `.Secret()` call.

## Types

### `PlainSecret[T]`

Stores the value in plaintext memory. Suitable when you simply want masking in logs and CLI output.

```go
s := secrets.NewSecret("my-api-key")
s.String()   // "*********"  — masked
s.Secret()   // "my-api-key" — explicit retrieval
```

### `EncryptedSecret[T]`

Encrypts the value with AES-256-GCM using a per-process random key (or a key you supply). The plaintext never sits in memory after the initial `Set`.

```go
es := secrets.NewEncryptedSecret("my-api-key")
es.String()   // "*****"      — masked
es.Secret()   // "my-api-key" — decrypts on demand
```

## The `Secret[T]` interface

Both types satisfy the `Secret[T]` interface:

```go
type Secret[T any] interface {
    encoding.TextMarshaler    // always returns masked text
    encoding.TextUnmarshaler  // parses the real value
    json.Marshaler            // always marshals as masked text
    json.Unmarshaler          // unmarshals the real value
    pflag.Value               // String / Set / Type — for CLI flags

    Secret() T                // returns the plaintext value
    Empty() bool
    MarshalSecret() ([]byte, error) // returns the plaintext bytes
}
```

## Supported value types

`T` can be anything that can be (un)marshaled:

| Type | Marshaling used |
|---|---|
| `string` | direct |
| `[]byte` | direct |
| `encoding.TextMarshaler` / `encoding.TextUnmarshaler` | text |
| `json.Marshaler` / `json.Unmarshaler` | JSON |
| any other struct / value | `encoding/json` fallback |

## Usage

### Basic string secret

```go
import "github.com/zauberhaus/secrets"

s := secrets.StringSecret("super-secret")
fmt.Println(s)          // ""  (empty → no asterisks)

s2 := secrets.StringSecret("hunter2")
fmt.Println(s2)         // "*******"
fmt.Println(s2.Secret()) // "hunter2"
```

### Byte-slice secret

```go
b := secrets.BytesSecret([]byte("raw-token"))
b.Secret() // []byte("raw-token")
```

### Custom type

```go
type Credentials struct {
    User string `json:"user"`
    Pass string `json:"pass"`
}

creds := secrets.NewSecret(Credentials{User: "alice", Pass: "s3cr3t"})
creds.String()  // "*****"
creds.Secret()  // Credentials{User:"alice", Pass:"s3cr3t"}
```

### JSON round-trip (value is always masked)

```go
es := secrets.NewEncryptedSecret("tok_live_abc123")

data, _ := json.Marshal(es)
fmt.Println(string(data)) // "*****"

var es2 secrets.EncryptedSecret[string]
json.Unmarshal([]byte(`"tok_live_abc123"`), &es2)
es2.Secret() // "tok_live_abc123"
```

### Cobra / pflag CLI flag

Both types implement `pflag.Value`, so they register directly as cobra flags.
The value is masked in `--help` output; only the command handler sees the real value.

```go
var apiKey = secrets.NewEncryptedSecret("")

func init() {
    rootCmd.Flags().Var(apiKey, "api-key", "API key (masked in logs)")
}

func run(cmd *cobra.Command, args []string) {
    client := newClient(apiKey.Secret()) // plaintext only here
}
```

```
$ myapp --help
Flags:
  --api-key string   API key (masked in logs) (default *****)

$ myapp --api-key tok_live_abc123
# apiKey.Secret() == "tok_live_abc123" inside run()
```

### Custom encryption key

By default a random 256-bit key is generated at process start. To use a deterministic key (e.g. from a KMS), call `SetKey` **before** any `EncryptedSecret` is created:

```go
func main() {
    key := fetchKeyFromKMS() // must be exactly 32 bytes
    secrets.SetKey(key)

    // now create encrypted secrets as normal
}
```

> `SetKey` panics if a key has already been initialized.

## Installation

```sh
go get github.com/zauberhaus/secrets
```

## License

MIT
