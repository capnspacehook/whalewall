package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

type DB struct {
	*Queries
	db *sql.DB
}

func NewDB(ctx context.Context, db *sql.DB) (*DB, error) {
	q, err := Prepare(ctx, db)
	if err != nil {
		return nil, err
	}

	return &DB{
		Queries: q,
		db:      db,
	}, nil
}

type TX struct {
	*Queries
	logger *zap.Logger
}

func (d *DB) Begin(ctx context.Context, logger *zap.Logger) (*TX, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("error beginning database transaction: %w", err)
	}

	return &TX{
		Queries: d.WithTx(tx),
		logger:  logger,
	}, nil
}

func (t *TX) Rollback(ctx context.Context) bool {
	if err := t.tx.Rollback(); err != nil {
		if errors.Is(err, sql.ErrTxDone) {
			return false
		}
		t.logger.Error("error rolling back database transaction", zap.Error(err))
		return false
	}

	return true
}

func (t *TX) Commit(ctx context.Context) error {
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("error committing database transaction: %w", err)
	}

	return nil
}
