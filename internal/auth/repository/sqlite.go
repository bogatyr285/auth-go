package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
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
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
		CREATE TABLE IF NOT EXISTS tokens (
			id INTEGER PRIMARY KEY,
			user_id INT NOT NULL,
			token text  NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL,
			expired_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
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

	if _, err = stmt.Exec(u.Username, u.Password); err != nil {
		return err
	}

	return nil
}

func (s *SQLLiteStorage) FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT id, password FROM users WHERE username = ?`)
	if err != nil {
		return entity.UserAccount{}, err
	}

	var pswdFromDB string
	var ID int

	if err = stmt.QueryRow(username).Scan(&ID, &pswdFromDB); err != nil {
		return entity.UserAccount{}, err
	}

	return entity.UserAccount{
		ID:       ID,
		Username: username,
		Password: pswdFromDB,
	}, nil
}

func (s *SQLLiteStorage) GetUserById(ctx context.Context, ID int) (entity.UserAccount, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT username FROM users WHERE ID = ?`)
	if err != nil {
		return entity.UserAccount{}, err
	}

	var username string
	if err = stmt.QueryRow(ID).Scan(&username); err != nil {
		return entity.UserAccount{}, fmt.Errorf("failed to get username: %s", err)
	}

	return entity.UserAccount{
		Username: username,
		Password: "",
	}, nil
}

func (s *SQLLiteStorage) GenerateUserToken(ctx context.Context, userID int) (uuid.UUID, error) {
	newUUID, err := uuid.NewUUID()
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to generate uuid: %s", err)
	}

	currentTime := time.Now().UTC()
	expiredAt := currentTime.Add(24 * 30 * time.Hour)

	query := `INSERT INTO tokens(user_id, token, created_at, expired_at) VALUES(?,?,?,?)`
	_, err = s.db.ExecContext(ctx, query, userID, newUUID, currentTime, expiredAt)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to insert token: %s", err)
	}

	return newUUID, nil
}

func (s *SQLLiteStorage) ExistsToken(ctx context.Context, token string) (bool, error) {
	query := `SELECT id FROM tokens WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return false, fmt.Errorf("failed to check token: %s", err)
	}

	return true, nil
}

func (s *SQLLiteStorage) SelectUserByToken(ctx context.Context, token string) (entity.UserAccount, error) {
	query := `SELECT u.id, u.username FROM users u JOIN tokens t ON u.id = t.user_id WHERE token = ?`
	row := s.db.QueryRowContext(ctx, query, token)
	if row.Err() != nil {
		return entity.UserAccount{}, fmt.Errorf("failed to check token: %s", row.Err())
	}

	var ID int
	var username string
	if err := row.Scan(&ID, &username); err != nil {
		return entity.UserAccount{}, fmt.Errorf("failed to check token: %s", err)
	}

	return entity.UserAccount{
		ID:       ID,
		Username: username,
		Password: "",
	}, nil
}

func (s *SQLLiteStorage) ExistsUserByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT id FROM users WHERE username = ?`

	row := s.db.QueryRowContext(ctx, query, username)
	if row.Err() != nil {
		return false, fmt.Errorf("failed to check username: %s", row.Err())
	}

	var ID int
	if err := row.Scan(&ID); err != nil {
		return false, fmt.Errorf("failed to check username: %s", err)
	}

	return true, nil
}
