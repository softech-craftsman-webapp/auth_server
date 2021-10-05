package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model

	ID              string         `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	Name            string         `gorm:"type:varchar(64);not null" json:"name"`
	Email           string         `gorm:"type:varchar(120);not null;unique" json:"email"`
	Password        string         `gorm:"type:varchar(64);not null" json:"password"`
	EmailVerifiedAt *time.Time     `gorm:"type:timestamp;" json:"email_verified_at"`
	CreatedAt       time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"deleted_at"`

	// Relations
	Verification []Verification `gorm:"foreignKey:user_id"`
	Auth         Auth           `gorm:"foreignKey:user_id"`
}
