package model

import (
	"time"

	"gorm.io/gorm"
)

type Auth struct {
	gorm.Model

	ID        string         `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	Token     string         `gorm:"type:varchar(255);unique_index" json:"token"`
	UserID    string         `gorm:"type:uuid;not null" json:"user_id"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}
