# secrets

A Go library for handling sensitive values (passwords, tokens, API keys, …) safely.
Secrets are never exposed through `String()`, `%#v`, JSON marshaling, parse errors, or flag help text — only through an explicit `.Secret()` call.

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

`GuardedSecret` is safe for concurrent use. `PlainSecret`, `EncryptedSecret` and `StringSecret` are safe for concurrent reads, but must not be mutated (`Set`, `UnmarshalText`, `UnmarshalJSON`, `Destroy`) concurrently with other access — `Destroy` wipes the stored bytes in place, so a concurrent read can fail or panic.

> ⚠️ Calling `memguard.Purge()` rotates memguard's session key, after which every existing `GuardedSecret` is permanently undecryptable and `Secret()` panics. Each read also briefly `mlock`s a memory page; in hot paths, read the value once and reuse it rather than calling `Secret()` per request.

### `EncryptedSecret[T]`

Encrypts the value with AES-256-GCM using a per-process random key (or a key you supply). The value is stored encrypted and only decrypted on demand.

To reduce exposure to memory dumps:

- The AES key is sealed in an [memguard](https://github.com/awnumar/memguard) enclave — `mlock`ed, guard-paged, excluded from swap and core dumps — and only opened for the moment the cipher is created.
- Transient plaintext buffers in `Set`/`Secret`/`ID` are wiped immediately after use.

Limits: the value returned by `Secret()` lives in regular memory under the caller's control, `string` values are immutable and cannot be wiped, and Go's GC may copy memory. This reduces how much plaintext is resident and for how long — it does not make a memory dump safe.

`NewEncryptedSecret` **panics for `string` types** (including named string types), because the immutable string handed to it can never be wiped. Use `[]byte` so buffers can actually be wiped, or [`StringSecret`](#stringsecret) for string-valued secrets. (An `EncryptedSecret[string]` zero value can still be filled through `Set` or JSON.)

> Custom `T` types must follow the standard `UnmarshalText`/`UnmarshalJSON` contract and **copy** the input if they retain it — the library wipes the decrypted buffer after unmarshaling.

```go
es := secrets.NewEncryptedSecret([]byte("my-api-key"))
es.String()   // "*****"                — masked
es.Secret()   // []byte("my-api-key")   — decrypts on demand
```

### `StringSecret`

A non-generic, `[]byte`-backed type for string-valued secrets (e.g. CLI flags). The slice itself holds the AES-256-GCM ciphertext, encrypted with the same package key (and `SetKey`) as `EncryptedSecret`, so no wrapper struct is needed. It satisfies `Secret[[]byte]`: `Secret()` returns the plaintext as a caller-owned `[]byte` that can be wiped after use.

```go
s := secrets.NewStringSecret("my-api-key") // Secret[[]byte] (a *StringSecret)
s.String()          // "*****"
string(s.Secret())  // "my-api-key"

// or from an existing *string (nil or empty yields an empty secret):
val := "my-api-key"
s2 := secrets.NewStringFlag(&val)
```

The same key-management and memory-exposure caveats as `EncryptedSecret` apply.

## The `Secret[T]` interface

All four types satisfy the `Secret[T]` interface (`StringSecret` as `Secret[[]byte]`, via its pointer):

```go
type Secret[T any] interface {
    encoding.TextMarshaler    // always returns masked text
    encoding.TextUnmarshaler  // parses the real value
    json.Marshaler            // always marshals as masked text
    json.Unmarshaler          // unmarshals the real value
    pflag.Value               // String / Set / Type — for CLI flags

    Secret() T                        // returns the plaintext value
    Empty() bool
    Hash() ([32]byte, error)          // unsalted SHA-256 hash of the plaintext bytes
    ID() (string, error)              // short, stable identifier derived from the value
    MarshalSecret() ([]byte, error)   // returns the plaintext bytes
    Destroy()                         // wipes the value; the secret reads as empty afterwards
    Equal(other Secret[T]) bool       // constant-time comparison of the hashes; empty secrets are never equal
}
```

Behavior shared by all types:

- `Set("")` / `UnmarshalText(nil)` clears the secret.
- Parse errors never quote the input: they wrap `secrets.ErrInvalidValue` and only name the target type (`secrets: invalid value for secret of type int`).
- Writing to a nil secret pointer returns `secrets.ErrNilSecret` instead of silently dropping the value. Read methods on a nil pointer behave like an empty secret.
- `Hash()`, `ID()` and `Equal` are unsalted; see the ID section below for the dictionary-attack caveat.

## Supported value types

`T` can be anything that can be (un)marshaled:

| Type | Marshaling used |
|---|---|
| `string` | direct |
| `[]byte` | direct |
| `encoding.TextMarshaler` / `encoding.TextUnmarshaler` | text |
| `json.Marshaler` / `json.Unmarshaler` | JSON |
| Private keys: `crypto.Signer` (`*rsa.PrivateKey`, `*ecdsa.PrivateKey`, `ed25519.PrivateKey`, …), or a broad interface holding one (`crypto.Signer`, `crypto.PrivateKey`, `any`) | PKCS8 (`x509.MarshalPKCS8PrivateKey`) |
| Public keys: `*rsa.PublicKey`, `*ecdsa.PublicKey`, `ed25519.PublicKey`, …, or a broad interface holding one (`crypto.PublicKey`, `any`) | PKIX (`x509.MarshalPKIXPublicKey`), prefixed with a 1-byte tag |
| `*jwt.Token` ([golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt)) | the token's compact string (`Token.Raw`) |
| any other struct / value | `encoding/json` fallback |

## Usage

### Basic string secret

```go
import "github.com/zauberhaus/secrets"

var s secrets.StringSecret
fmt.Println(s)          // ""  (empty → no asterisks)

s2 := secrets.NewStringSecret("hunter2")
fmt.Println(s2)                  // "*****"

plain := s2.Secret()             // []byte("hunter2"), owned by the caller
defer secrets.Wipe(plain)
```

### Byte-slice secret

```go
b := secrets.NewSecret([]byte("raw-token"))
b.Secret() // []byte("raw-token")
```

### Secret from an environment variable

`NewEncryptedSecretFromEnv` reads a variable into an `EncryptedSecret[[]byte]` and then **unsets** it, so child processes and later `os.Getenv` calls no longer see it. A missing variable yields an empty secret. The original value may still remain in the process's initial environment block (e.g. `/proc/self/environ` on Linux), which cannot be wiped from Go.

```go
token := secrets.NewEncryptedSecretFromEnv("API_TOKEN")
if token.Empty() {
    log.Fatal("API_TOKEN not set")
}
```

### Wiping plaintext buffers

`Wipe` zeroes a byte slice (via `memguard.WipeBytes`). Use it on `[]byte` values returned by `Secret()` or `MarshalSecret()` once you're done with them.

```go
data, _ := es.MarshalSecret()
defer secrets.Wipe(data)
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

### Private/public key secret

`*rsa.PrivateKey`, `*ecdsa.PrivateKey`, `ed25519.PrivateKey`, and any value assignable to `crypto.Signer` are encoded as PKCS8 instead of JSON. Their public-key counterparts (`*rsa.PublicKey`, `*ecdsa.PublicKey`, `ed25519.PublicKey`, …) are encoded as PKIX, prefixed with a 1-byte tag.

The tag exists because a public key type has no marker interface to check `T` against the way `crypto.Signer` lets private keys skip straight to the right parser: without it, decoding a public key stored under a broad interface (`any`, `crypto.PublicKey`) would need to try a PKCS8 parse, watch it fail, and only then try PKIX. The tag lets that case go straight to PKIX in one parse. It only appears on public-key output — every other type's `MarshalSecret()` bytes are unprefixed, exactly as before. Untagged public key DER (loaded from a file, or written before this existed) still decodes correctly by falling back to the old try-both-parsers path.

```go
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

es := secrets.NewEncryptedSecret(key)
es.Secret() // *ecdsa.PrivateKey, equal to key

// Also works when T is a broad interface:
signer := secrets.NewEncryptedSecret[crypto.Signer](key)
signer.Secret() // crypto.Signer wrapping the *ecdsa.PrivateKey

pub := secrets.NewEncryptedSecret(key.Public())
pub.Secret() // crypto.PublicKey wrapping the *ecdsa.PublicKey
```

> Comparing decoded keys with `==` or `reflect.DeepEqual` is unreliable — RSA keys in particular cache an internal, lazily-computed FIPS-mode shadow copy that isn't guaranteed byte-identical between two otherwise-equal keys. Use the key's own `Equal(x crypto.PrivateKey/PublicKey) bool` method instead.

### JWT secret

`*jwt.Token` is stored as its compact string form (`Token.Raw`), so only an already-parsed or already-signed token round-trips — one built with `jwt.New`/`jwt.NewWithClaims` and never turned into a string has an empty `Raw`.

Reading it back parses the string **without verifying its signature** (`jwt.NewParser().ParseUnverified`): this library's AES-GCM encryption already gives the stored bytes confidentiality and integrity, so re-checking the JWT's own signature on every read isn't needed for at-rest storage. If you hand the decoded token to something that trusts its claims for authorization, verify it against the appropriate key first.

```go
signed, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user123"}).
    SignedString([]byte("signing-key"))
tok, _, _ := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})

es := secrets.NewEncryptedSecret(tok)
es.Secret().Raw // == signed
```

### JSON round-trip (value is always masked)

```go
s := secrets.NewStringSecret("tok_live_abc123")

data, _ := json.Marshal(s)
fmt.Println(string(data)) // "*****"

var s2 secrets.StringSecret
json.Unmarshal([]byte(`"tok_live_abc123"`), &s2)
string(s2.Secret()) // "tok_live_abc123"
```

### Cobra / pflag CLI flag

All types implement `pflag.Value`, so they register directly as cobra flags.
The value is masked in `--help` output; only the command handler sees the real value.

```go
var apiKey = secrets.NewStringSecret("")

func init() {
    rootCmd.Flags().Var(apiKey, "api-key", "API key (masked in logs)")
}

func run(cmd *cobra.Command, args []string) {
    key := apiKey.Secret() // []byte copy owned by the caller
    defer secrets.Wipe(key)

    client := newClient(key) // plaintext only here
}
```

```
$ myapp --help
Flags:
  --api-key string   API key (masked in logs) (default *****)

$ myapp --api-key tok_live_abc123
# string(apiKey.Secret()) == "tok_live_abc123" inside run()
```

pflag quotes the raw argument in its invalid-value errors (`invalid argument "…" for "--pin" flag`). Install `SanitizeFlagError` so a mistyped secret is not echoed to the terminal or logs; it only rewrites errors for flags that hold a secret:

```go
rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
    return secrets.SanitizeFlagError(err)
})
```

A plain `pflag.FlagSet` with `ExitOnError` (the default for `pflag.CommandLine`) prints the unsanitized error itself before exiting; use `ContinueOnError` and pass the returned error through `SanitizeFlagError`.

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

> `SetKey` panics if a key has already been initialized or if the key is not exactly 32 bytes. The key is moved into a locked memory enclave and the caller's slice is **wiped** in the process (also when `SetKey` panics). Cipher texts are bound to their type through GCM associated data, so an `EncryptedSecret[[]byte]` ciphertext cannot be decrypted as, say, an `EncryptedSecret[int]` or a `StringSecret`.

## Installation

```sh
go get github.com/zauberhaus/secrets
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
