package config

import (
	model "auth_server/model"
)

func Migrate() {
	db := GetDB()

	// Auto Migration
	db.AutoMigrate(&model.User{})
	db.AutoMigrate(&model.Verification{})
	db.AutoMigrate(&model.Auth{})

	CloseDB(db).Close()
}
