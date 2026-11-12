package secrets

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/spf13/pflag"
)

var (
	// ErrInvalidValue is returned (wrapped) when input cannot be parsed into
	// a secret. The underlying parser error is deliberately dropped because
	// it may quote parts of the secret.
	ErrInvalidValue = errors.New("secrets: invalid value")

	// ErrNilSecret is returned when a value is written to a nil secret
	// pointer, so the write cannot be silently lost.
	ErrNilSecret = errors.New("secrets: write to nil secret")
)

func invalidValue[T any]() error {
	return fmt.Errorf("%w for secret of type %v", ErrInvalidValue, reflect.TypeFor[T]())
}

// SanitizeFlagError removes the raw argument from a pflag
// [pflag.InvalidValueError] when the flag holds a secret, so the value does
// not end up on stderr or in logs. Other errors are returned unchanged.
//
// With cobra, install it once on the root command:
//
//	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
//		return secrets.SanitizeFlagError(err)
//	})
//
// A [pflag.FlagSet] using [pflag.ExitOnError] (the default for
// [pflag.CommandLine]) prints the unsanitized error itself before exiting;
// use [pflag.ContinueOnError] and sanitize the returned error instead.
func SanitizeFlagError(err error) error {
	var ive *pflag.InvalidValueError
	if !errors.As(err, &ive) {
		return err
	}

	flag := ive.GetFlag()
	if flag == nil {
		return err
	}

	if _, ok := flag.Value.(interface{ MarshalSecret() ([]byte, error) }); !ok {
		return err
	}

	name := "--" + flag.Name
	if flag.Shorthand != "" && flag.ShorthandDeprecated == "" {
		name = "-" + flag.Shorthand + ", " + name
	}

	return fmt.Errorf("invalid argument for %q flag: %w", name, ive.Unwrap())
}
