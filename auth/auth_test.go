package auth

import (
	"testing"
	"time"
)

func TestHash(t *testing.T) {
	hash, error := Hash("test")

	if error != nil {
		t.Errorf("Error: %d", error)
	}

	if string(hash) == "" {
		t.Errorf("Hash is empty")
	}
}

func TestVerifyPassword(t *testing.T) {
	hash, error := Hash("test")

	if error != nil {
		t.Errorf("Error: %d", error)
	}

	error = VerifyPassword(string(hash), "test")

	if error != nil {
		t.Errorf("Error: %d", error)
	}
}

func TestGenerateSalt(t *testing.T) {
	salt := GenerateSalt("test@example.com", "uuid")

	if string(salt) == "" {
		t.Errorf("Salt is empty")
	}
}

func TestGenerateTokenAndSalt(t *testing.T) {
	token, salt := GenerateTokenAndSalt("test@example.com", "uuid")

	if string(token) == "" {
		t.Errorf("Token is empty")
	}

	if string(salt) == "" {
		t.Errorf("Salt is empty")
	}
}

func TestVerifyEmailToken(t *testing.T) {
	token, salt := GenerateTokenAndSalt("test@example.com", "uuid")

	isVerified := VerifyEmailToken("test@example.com", "uuid", salt, token)

	if !isVerified {
		t.Errorf("Token is not verified")
	}
}

func TestTimeValidation(t *testing.T) {
	now := time.Now()
	expire := now.Add(time.Minute * 1)
	minute := int64(1)

	isTimeVerified := TimeValidation(expire, minute)

	if !isTimeVerified {
		t.Errorf("Time is not verified")
	}
}
