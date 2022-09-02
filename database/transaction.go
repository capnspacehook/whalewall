package database

import (
	"context"
	"database/sql"
	"errors"
	"log"
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
}

func (d *DB) Begin(ctx context.Context) (*TX, bool) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		log.Printf("error beginning database transaction: %v", err)
		return nil, false
	}

	return &TX{
		Queries: d.WithTx(tx),
	}, true
}

func (t *TX) Rollback(ctx context.Context) bool {
	if err := t.tx.Rollback(); err != nil {
		if errors.Is(err, sql.ErrTxDone) {
			return false
		}
		log.Printf("error rolling back database transaction: %v", err)
		return false
	}

	return true
}

func (t *TX) Commit(ctx context.Context) bool {
	if err := t.tx.Commit(); err != nil {
		log.Printf("error committing database transaction: %v", err)
		return false
	}

	return true
}
