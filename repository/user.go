package repository

import (
	"context"
	"time"

	"github.com/ebrym/ers/data"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
)

// UserRepository has the implementation of the db methods.
type UserRepository struct {
	db     *sqlx.DB
	logger hclog.Logger
}

// NewUserRepository returns a new UserRepository instance
func NewUserRepository(db *sqlx.DB, logger hclog.Logger) *UserRepository {
	return &UserRepository{db, logger}
}

// Create inserts the given user into the database
func (repo *UserRepository) Create(ctx context.Context, user *data.User) error {
	user.ID = uuid.NewV4().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	repo.logger.Info("creating user", hclog.Fmt("%#v", user))
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := repo.db.ExecContext(ctx, query, user.ID, user.Email, user.Username, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// GetUserByEmail retrieves the user object having the given email, else returns error
func (repo *UserRepository) GetUserByEmail(ctx context.Context, email string) (*data.User, error) {
	repo.logger.Debug("querying for user with email", email)
	query := "select * from users where email = $1"
	var user data.User
	if err := repo.db.GetContext(ctx, &user, query, email); err != nil {
		return nil, err
	}
	repo.logger.Debug("read users", hclog.Fmt("%#v", user))
	return &user, nil
}

// GetUserByID retrieves the user object having the given ID, else returns error
func (repo *UserRepository) GetUserByID(ctx context.Context, userID string) (*data.User, error) {
	repo.logger.Debug("querying for user with id", userID)
	query := "select * from users where id = $1"
	var user data.User
	if err := repo.db.GetContext(ctx, &user, query, userID); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUsername updates the username of the given user
func (repo *UserRepository) UpdateUsername(ctx context.Context, user *data.User) error {
	user.UpdatedAt = time.Now()

	query := "update users set username = $1, updatedat = $2 where id = $3"
	if _, err := repo.db.ExecContext(ctx, query, user.Username, user.UpdatedAt, user.ID); err != nil {
		return err
	}
	return nil
}

// UpdateUserVerificationStatus updates user verification status to true
func (repo *UserRepository) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {

	query := "update users set isverified = $1 where email = $2"
	if _, err := repo.db.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// StoreMailVerificationData adds a mail verification data to db
func (repo *UserRepository) StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error {

	query := "insert into verifications(email, code, expiresat, type) values($1, $2, $3, $4)"
	_, err := repo.db.ExecContext(ctx, query, verificationData.Email, verificationData.Code, verificationData.ExpiresAt, verificationData.Type)
	return err
}

// GetMailVerificationCode retrieves the stored verification code.
func (repo *UserRepository) GetVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) (*data.VerificationData, error) {

	query := "select * from verifications where email = $1 and type = $2"

	var verificationData data.VerificationData
	if err := repo.db.GetContext(ctx, &verificationData, query, email, verificationDataType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

// DeleteMailVerificationData deletes a used verification data
func (repo *UserRepository) DeleteVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) error {

	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.db.ExecContext(ctx, query, email, verificationDataType)
	return err
}

// UpdatePassword updates the user password
func (repo *UserRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {

	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}
