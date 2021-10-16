package config

import (
	"database/sql"
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetDB() *gorm.DB {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")
	timezone := os.Getenv("TZ")

	connection := fmt.Sprintf(
		"host=%v port=%v user=%v dbname=%v password=%v sslmode=%v TimeZone=%v",
		host,
		port,
		user,
		dbname,
		password,
		sslmode,
		timezone,
	)

	db, err := gorm.Open(
		postgres.Open(connection),
		&gorm.Config{},
	)

	if err != nil {
		panic(err)
	}

	return db
}

func CloseDB(db *gorm.DB) *sql.DB {
	sqlDB, _ := db.DB()

	return sqlDB
}
