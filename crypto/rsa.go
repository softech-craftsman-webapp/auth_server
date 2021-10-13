package crypto

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt"
)

/*
   |--------------------------------------------------------------------------
   | RSA Public Key String
   |--------------------------------------------------------------------------
*/
func RsaPublicKeyString() string {
	publicKeyString := []byte(ReadFile(os.Getenv("ACCESS_PUBLIC_PEM_FILE")))

	return string(publicKeyString)
}

/*
   |--------------------------------------------------------------------------
   | RSA Public Key @Access
   |--------------------------------------------------------------------------
*/
func RsaAccessPublicKey() (*rsa.PublicKey, error) {
	publicKey := []byte(ReadFile(os.Getenv("ACCESS_PUBLIC_PEM_FILE")))
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Refresh
   |--------------------------------------------------------------------------
*/
func RsaRefreshPublicKey() (*rsa.PublicKey, error) {
	publicKey := []byte(ReadFile(os.Getenv("REFRESH_PUBLIC_PEM_FILE")))
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func RsaAccessPrivateKey() (*rsa.PrivateKey, error) {
	privateKey := []byte(ReadFile(os.Getenv("ACCESS_PRIVATE_PEM_FILE")))
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func RsaRefreshPrivateKey() (*rsa.PrivateKey, error) {
	privateKey := []byte(ReadFile(os.Getenv("REFRESH_PRIVATE_PEM_FILE")))
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	return key, err
}
