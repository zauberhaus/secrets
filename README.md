# secrets

A Go library for handling sensitive values (passwords, tokens, API keys, …) safely.
Secrets are never exposed through `String()`, JSON marshaling, or flag help text — only through an explicit `.Secret()` call.

## Types

### `PlainSecret[T]`

Stores the value in plaintext memory. Suitable when you simply want masking in logs and CLI output.

```go
s := secrets.NewSecret("my-api-key")
s.String()   // "*****"      — masked (fixed width, does not reveal length)
s.Secret()   // "my-api-key" — explicit retrieval
```

### `GuardedSecret[T]`

Stores the serialized plaintext directly in a [memguard](https://github.com/awnumar/memguard) Enclave: `mlock`'d, guard-paged, excluded from swap and core dumps, and encrypted at rest with a per-process in-memory key managed entirely by memguard. No user-supplied key is required.

```go
s := secrets.NewGuardedSecret("my-api-key")
s.String()   // "*****"      — masked
s.Secret()   // "my-api-key" — decrypts from protected memory on demand
s.Destroy()  // drop the sealed value; the secret reads as empty afterwards
```

**When to choose `GuardedSecret` over `EncryptedSecret`:** use `GuardedSecret` for the strongest in-process memory protection when you don't need to persist or share the encrypted form. Use `EncryptedSecret` when you need a user-supplied or KMS-derived key.

`GuardedSecret` is safe for concurrent use. `PlainSecret` and `EncryptedSecret` are safe for concurrent reads, but must not be mutated (`Set`, `UnmarshalText`, `UnmarshalJSON`) concurrently with other access.

> ⚠️ Calling `memguard.Purge()` rotates memguard's session key, after which every existing `GuardedSecret` is permanently undecryptable and `Secret()` panics. Each read also briefly `mlock`s a memory page; in hot paths, read the value once and reuse it rather than calling `Secret()` per request.

### `EncryptedSecret[T]`

Encrypts the value with AES-256-GCM using a per-process random key (or a key you supply). The value is stored encrypted and only decrypted on demand.

To reduce exposure to memory dumps:

- The AES key is sealed in an [memguard](https://github.com/awnumar/memguard) enclave — `mlock`ed, guard-paged, excluded from swap and core dumps — and only opened for the moment the cipher is created.
- Transient plaintext buffers in `Set`/`Secret`/`ID` are wiped immediately after use.

Limits: the value returned by `Secret()` lives in regular memory under the caller's control, `string` values are immutable and be wiped, and Go's GC may cannot  copy memory. This reduces how much plaintext is resident and for how long — it does not make a memory dump safe. For `T = string`/`[]byte`, prefer `[]byte` so buffers can actually be wiped.

> Custom `T` types must follow the standard `UnmarshalText`/`UnmarshalJSON` contract and **copy** the input if they retain it — the library wipes the decrypted buffer after unmarshaling.

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

    Secret() T                        // returns the plaintext value
    Empty() bool
    ID() (string, error)              // short, stable identifier derived from the value
    MarshalSecret() ([]byte, error)   // returns the plaintext bytes
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
fmt.Println(s2)         // "*****"
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

### Identifying a secret without exposing it

`ID()` returns a short, stable Base58-encoded identifier derived from the SHA-256 hash of the secret's plaintext bytes (first 8 bytes of the hash). It lets you correlate log entries or cache keys against a specific secret value without ever logging the value itself.

```go
s := secrets.NewSecret("tok_live_abc123")
id, err := s.ID()
fmt.Println(id) // e.g. "4i7vEoxMskW" — same every time for the same value
```

The same value always produces the same ID; different values produce different IDs (with high probability).

> ⚠️ The ID is an unsalted hash of the plaintext. For low-entropy secrets (human-chosen passwords), an attacker who sees the ID can confirm guesses offline via a dictionary attack. Only expose IDs of high-entropy secrets (random tokens, generated keys).

### Custom encryption key

By default a random 256-bit key is generated at process start. To use a deterministic key (e.g. from a KMS), call `SetKey` **before** any `EncryptedSecret` is created:

```go
func main() {
    key := fetchKeyFromKMS() // must be exactly 32 bytes
    secrets.SetKey(key)

    // now create encrypted secrets as normal
}
```

> `SetKey` panics if a key has already been initialized or if the key is not exactly 32 bytes. The key is moved into a locked memory enclave and the caller's slice is **wiped** in the process.

## Installation

```sh
go get github.com/zauberhaus/secrets
```

## License

MIT
