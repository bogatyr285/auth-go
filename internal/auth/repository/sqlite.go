package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bogatyr285/auth-go/internal/auth/entity"
	_ "github.com/mattn/go-sqlite3"
)

type SQLLiteStorage struct {
	db *sql.DB
}

func New(dbPath string) (SQLLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return SQLLiteStorage{}, err
	}
	stmt, err := db.Prepare(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username text not null,
		password text not null,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	_, err = stmt.Exec()
	if err != nil {
		return SQLLiteStorage{}, err
	}

	stmt, err = db.Prepare(`
	create index if not exists idx_username ON users(username);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}
	
	_, err = stmt.Exec()
	if err != nil {
		return SQLLiteStorage{}, err
	}

	stmt, err = db.Prepare(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY,
		token TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		issued_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		is_valid BOOLEAN DEFAULT TRUE,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	_, err = stmt.Exec()
	if err != nil {
		return SQLLiteStorage{}, err
	}

	stmt, err = db.Prepare(`
	CREATE INDEX IF NOT EXISTS idx_token ON refresh_tokens(token);
	`)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("db schema init err: %s", err)
	}

	_, err = stmt.Exec()
	if err != nil {
		return SQLLiteStorage{}, err
	}

	return SQLLiteStorage{db: db}, nil
}

func (s *SQLLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLLiteStorage) RegisterUser(ctx context.Context, u entity.UserAccount) error {
	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO users(username, password) VALUES(?,?)`)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(u.Username, u.Password); err != nil {
		return err
	}

	return nil
}

func (s *SQLLiteStorage) FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT password FROM users WHERE username = ?`)
	if err != nil {
		return entity.UserAccount{}, err
	}

	var pswdFromDB string

	if err := stmt.QueryRow(username).Scan(&pswdFromDB); err != nil {
		return entity.UserAccount{}, err
	}

	return entity.UserAccount{
		Username: username,
		Password: pswdFromDB,
	}, nil
}

func (s *SQLLiteStorage) StoreRefreshToken(token string, userID string, issuedAt, expiresAt time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (token, user_id, issued_at, expires_at, is_valid) VALUES ($1, $2, $3, $4, TRUE)",
		token, userID, issuedAt, expiresAt,
	)
	return err
}

func (s *SQLLiteStorage) IsRefreshTokenValid(token string) (bool, string, error) {
	var isValid bool
	var userID string
	err := s.db.QueryRow(
		"SELECT is_valid, user_id FROM refresh_tokens WHERE token = $1 AND expires_at > $2",
		token, time.Now(),
	).Scan(&isValid, &userID)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return isValid, userID, nil
}

func (s *SQLLiteStorage) RevokeRefreshToken(token string) error {
	_, err := s.db.Exec("UPDATE refresh_tokens SET is_valid = FALSE WHERE token = $1", token)
	return err
}
