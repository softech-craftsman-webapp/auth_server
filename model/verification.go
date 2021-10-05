package model

import (
	"time"

	"gorm.io/gorm"
)

type Verification struct {
	gorm.Model

	ID         string         `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	UserID     string         `gorm:"type:uuid;not null" json:"user_id"`
	Token      string         `gorm:"type:varchar(255);not null;unique" json:"token"`
	Salt       string         `gorm:"type:varchar(255);not null;unique" json:"salt"`
	VerifiedAt *time.Time     `gorm:"type:timestamp" json:"verified_at"`
	ValidUntil time.Time      `gorm:"type:timestamp;not null" json:"valid_until"`
	CreatedAt  time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}
