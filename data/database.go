package data

import (
	"fmt"

	"github.com/ebrym/ers/utils"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// NewConnection creates the connection to the database
func NewConnection(config *utils.Configurations, logger hclog.Logger) (*sqlx.DB, error) {

	var conn string

	if config.DBConn != "" {
		conn = config.DBConn
	} else {
		host := config.DBHost
		port := config.DBPort
		user := config.DBUser
		dbName := config.DBName
		password := config.DBPass
		conn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", host, port, user, dbName, password)
	}
	logger.Debug("connection string", conn)

	db, err := sqlx.Connect("postgres", conn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// NewConnection creates the connection to the database
func NewGormConnection(config *utils.Configurations, logger hclog.Logger) (*gorm.DB, error) {

	var conn string

	if config.DBConn != "" {
		conn = config.DBConn
	} else {
		host := config.DBHost
		port := config.DBPort
		user := config.DBUser
		dbName := config.DBName
		password := config.DBPass
		conn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", host, port, user, dbName, password)
	}
	logger.Debug("connection string", conn)

	//db, err := gorm.Open("postgres", conn)

	// https://github.com/go-gorm/postgres
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  conn,
		PreferSimpleProtocol: true, // disables implicit prepared statement usage
	}), &gorm.Config{})

	if err != nil {
		return nil, err
	}
	return db, nil
}
