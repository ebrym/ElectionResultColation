package data

import (
	"time"

	"github.com/ebrym/ers/utils"
	"github.com/hashicorp/go-hclog"
	"gorm.io/gorm"
)

type entity interface {
	AutoMigrate(logger hclog.Logger, configs *utils.Configurations, db *gorm.DB) bool
}

type user struct {
	gorm.Model
	email      string
	password   string
	psername   string
	tokenHash  string
	isVerified bool
}

type verification struct {
	email           string
	code            string
	expiresAt       time.Time
	verifcationtype string
}

// Migrate the schema of database if needed
func AutoMigrate(logger hclog.Logger, configs *utils.Configurations, db *gorm.DB) bool {
	// db, err := NewGormConnection(configs, logger)
	// if err != nil {
	// 	logger.Error("unable to migrate data", "error", err)
	// 	return false
	// }

	logger.Info("Migrating data", "error", "")
	db.AutoMigrate(&user{})
	db.AutoMigrate(&verification{})

	return true
}
