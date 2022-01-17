package handlers

import (
	"fmt"

	"github.com/ebrym/ers/repository"
	"github.com/ebrym/ers/service"
	"github.com/ebrym/ers/utils"
	"github.com/hashicorp/go-hclog"
)

// UserKey is used as a key for storing the User object in context at middleware
type UserKey struct{}

// UserIDKey is used as a key for storing the UserID in context at middleware
type UserIDKey struct{}

// VerificationDataKey is used as the key for storing the VerificationData in context at middleware
type VerificationDataKey struct{}

// UserHandler wraps instances needed to perform operations on user object
type AuthenticationHandler struct {
	logger      hclog.Logger
	configs     *utils.Configurations
	validator   *utils.Validation
	repo        repository.IUserRepository
	authService service.Authentication
	mailService service.MailService
}

// NewUserHandler returns a new UserHandler instance
func NewAuthHandler(l hclog.Logger, c *utils.Configurations, v *utils.Validation, r repository.IUserRepository, auth service.Authentication, mail service.MailService) *AuthenticationHandler {
	return &AuthenticationHandler{
		logger:      l,
		configs:     c,
		validator:   v,
		repo:        r,
		authService: auth,
		mailService: mail,
	}
}

var ErrUserAlreadyExists = fmt.Sprintf("User already exists with the given email")
var ErrUserNotFound = fmt.Sprintf("No user account exists with given email. Please sign in first")
var UserCreationFailed = fmt.Sprintf("Unable to create user.Please try again later")

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
var PgNoRowsMsg = "no rows in result set"
