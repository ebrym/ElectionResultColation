package main

import (
	"github.com/ebrym/ers/data"
	"github.com/ebrym/ers/utils"
)

func main() {

	logger := utils.NewLogger()

	configs := utils.NewConfigurations(logger)

	// validator contains all the methods that are need to validate the user json in request
	//validator := utils.NewValidation()

	// create a new connection to the postgres db store
	db, err := data.NewGormConnection(configs, logger)
	if err != nil {
		logger.Error("unable to connect to db", "error", err)
		panic(err)
	}

	migrate := data.AutoMigrate(logger, configs, db)
	if migrate == false {
		logger.Error("unable to connect to db", "error", err)
		panic(err)
	}
	defer db.Close()
}
