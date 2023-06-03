package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"modernc.org/sqlite"
)

const (
	retries = 100
	timeout = 10 * time.Millisecond

	SQLITE_BUSY = 5
)

type DB interface {
	Querier
	Begin(ctx context.Context, logger *zap.Logger) (TX, error)
	io.Closer
}

type db struct {
	*Queries
	db dbtx
}

type dbtx interface {
	DBTX
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

type dbRetrier struct {
	*sql.DB
}

func (d *dbRetrier) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return retryIfBusy(func() (sql.Result, error) {
		return d.DB.ExecContext(ctx, query, args...)
	})
}

func (d *dbRetrier) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return retryIfBusy(func() (*sql.Rows, error) {
		return d.DB.QueryContext(ctx, query, args...)
	})
}

func (d *dbRetrier) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	row, _ := retryIfBusy(func() (*sql.Row, error) {
		row := d.DB.QueryRowContext(ctx, query, args...)
		return row, row.Err()
	})
	return row
}

func (d *dbRetrier) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return retryIfBusy(func() (*sql.Tx, error) {
		return d.DB.BeginTx(ctx, opts)
	})
}

// retryIfBusy will retry the provided function if the database is busy
// and return the result afterwards. If any other error other than
// SQLITE_BUSY is encountered, it will be immediately returned.
func retryIfBusy[T any](f func() (T, error)) (T, error) {
	var ret T
	var err error

	for i := 0; i < retries; i++ {
		ret, err = f()
		if err == nil {
			return ret, nil
		}
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == SQLITE_BUSY {
			time.Sleep(timeout)
			continue
		}
		break
	}

	return ret, err
}

func NewDB(ctx context.Context, database *sql.DB) (DB, error) {
	queries, err := Prepare(ctx, database)
	if err != nil {
		return nil, err
	}
	wrappedDB := &dbRetrier{
		DB: database,
	}
	queries.db = wrappedDB

	return &db{
		Queries: queries,
		db:      wrappedDB,
	}, nil
}

type TX interface {
	Querier
	Rollback() bool
	Commit() error
}

type tx struct {
	*Queries
	ctx    context.Context
	logger *zap.Logger
}

func (d *db) Begin(ctx context.Context, logger *zap.Logger) (TX, error) {
	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error beginning database transaction: %w", err)
	}

	return &tx{
		// the transaction doesn't need to be wrapped with dbRetrier
		// because '_txlock=immediate' is set, so if the transaction
		// is created successfully, it is guaranteed not to fail with
		// SQLITE_BUSY
		Queries: d.WithTx(transaction),
		ctx:     ctx,
		logger:  logger,
	}, nil
}

func (t *tx) Rollback() bool {
	if err := t.tx.Rollback(); err != nil {
		if errors.Is(err, sql.ErrTxDone) {
			return false
		}
		t.logger.Error("error rolling back database transaction", zap.Error(err))
		return false
	}

	return true
}

func (t *tx) Commit() error {
	if err := t.tx.Commit(); err != nil {
		if errors.Is(err, sql.ErrTxDone) && t.ctx.Err() != nil {
			err = t.ctx.Err()
		}
		return fmt.Errorf("error committing database transaction: %w", err)
	}

	return nil
}
