package whalewall

import (
	"context"
	"errors"
	"time"
)

// withTimeout runs f with a timeout derived from [context.WithTimeout].
// Using withTimeout guarantees that:
//
//   - ctx is only shadowed in withTimeout's scope
//   - The child context will have it's resources released immediately
//     after f returns
//
// The main goal of withTimeout is to prevent shadowing ctx with a
// context with a timeout, having that timeout expire and the next call
// that uses ctx immediately fail.
func withTimeout[T, E any](ctx context.Context, timeout time.Duration, f func(ctx context.Context) (T, E)) (T, E) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return f(ctx)
}

// ignoringErr calls f and discards the error if any error in the error
// tree matches errToIgnore.
func ignoringErr(f func() error, errToIgnore error) error {
	err := f()
	if err == nil || (err != nil && errors.Is(err, errToIgnore)) {
		return nil
	}
	return err
}
