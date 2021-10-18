package auth

import (
	config "auth_server/config"
	crypto "auth_server/crypto"
	mailer "auth_server/mailer"
	model "auth_server/model"
	view "auth_server/view"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

/*
   |--------------------------------------------------------------------------
   | Generate hash
   |--------------------------------------------------------------------------
*/
func Hash(password string) ([]byte, error) {
	// Structure => secret:password
	salted_password := []byte(os.Getenv("SECRET") + ":" + password)

	return bcrypt.GenerateFromPassword([]byte(salted_password), bcrypt.DefaultCost)
}

/*
   |--------------------------------------------------------------------------
   | Verify password
   |--------------------------------------------------------------------------
*/
func VerifyPassword(hashedPassword, password string) error {
	// Structure => secret:password
	salted_password := []byte(os.Getenv("SECRET") + ":" + password)

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(salted_password))
}

/*
   |--------------------------------------------------------------------------
   | Jwt token Generate
   |--------------------------------------------------------------------------
*/
func jwtGenerate(user view.UserAuthView, minute int) *jwt.Token {
	h := time.Minute * time.Duration(minute)

	claims := &view.JwtCustomClaims{
		user,
		jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix() - 1,
			ExpiresAt: time.Now().Add(h).Unix(),
		},
	}

	token := jwt.NewWithClaims(crypto.SigningMethod, claims)

	return token
}

/*
   |--------------------------------------------------------------------------
   | Create Access Token
   |--------------------------------------------------------------------------
*/
func CreateAccessToken(user view.UserAuthView, minute int) (string, error) {
	token := jwtGenerate(user, minute)

	signKey, error := crypto.AccessPrivateKey()
	if error != nil {
		log.Fatal("Error in Private Key Signing @Access")
	}

	return token.SignedString(signKey)
}

/*
   |--------------------------------------------------------------------------
   | Create Refresh Token
   |--------------------------------------------------------------------------
*/
func CreateRefreshToken(user view.UserAuthView, minute int) (string, error) {
	token := jwtGenerate(user, minute)

	signKey, error := crypto.RefreshPrivateKey()
	if error != nil {
		log.Fatal("Error in Private Key Signing @Refresh")
	}

	return token.SignedString(signKey)
}

/*
   |--------------------------------------------------------------------------
   | Generate Sha1
   |--------------------------------------------------------------------------
*/
func GenerateSalt(email string, id string) string {
	salt_hasher := sha256.New()
	salt_hasher.Write([]byte(uuid.New().String() + os.Getenv("SECRET")))
	salt := hex.EncodeToString(salt_hasher.Sum(nil))

	return salt
}

/*
   |--------------------------------------------------------------------------
   | Generate Token And Salt
   |--------------------------------------------------------------------------
*/
func GenerateTokenAndSalt(email string, id string) (string, string) {
	salt := GenerateSalt(email, id)
	hasher := sha256.New()

	// Structure => id:email:salt
	hasher.Write([]byte(id + ":" + email + ":" + salt))

	return hex.EncodeToString(hasher.Sum(nil)), salt
}

/*
   |--------------------------------------------------------------------------
   | Verify Email Token
   |--------------------------------------------------------------------------
*/
func VerifyEmailToken(email string, id string, salt string, token string) bool {
	hasher := sha256.New()

	// Structure => id:email:salt
	hasher.Write([]byte(id + ":" + email + ":" + salt))

	return hex.EncodeToString(hasher.Sum(nil)) == token
}

/*
   |--------------------------------------------------------------------------
   | Time Valid
   |--------------------------------------------------------------------------
*/
func TimeValidation(until time.Time, minute int64) bool {
	now := time.Now().Unix()
	valid := until.Unix()
	offset := 60 * minute

	log.Println(now, valid, offset)
	return valid-now >= offset
}

/*
   |--------------------------------------------------------------------------
   | Email Verification
   |--------------------------------------------------------------------------
*/
func EmailVertification(email string, id string, minute int64, action string) error {
	db := config.GetDB()

	// Send Verification
	token, salt := GenerateTokenAndSalt(email, id)

	emailVerification := &model.Verification{
		UserID:     id,
		Token:      token,
		Salt:       salt,
		ValidUntil: time.Now().Add(time.Minute * time.Duration(minute)),
	}

	result := db.Create(&emailVerification)

	if result.Error != nil {
		return result.Error
	}

	/*
		|----------------------------------------------------------------------
		| Mails
		|----------------------------------------------------------------------
	*/
	switch action {
	case "VERIFY-EMAIL":
		mailer.EmailVerificationSend(email, token)
	case "RESET-PASSWORD":
		mailer.ForgotPasswordSend(email, token)
	}

	config.CloseDB(db).Close()

	return nil
}
