package crypto

import (
	"crypto/ecdsa"
	"os"

	"github.com/golang-jwt/jwt"
)

/*
   |--------------------------------------------------------------------------
   | ECDSA Public Key String
   |--------------------------------------------------------------------------
*/
func EcdsaPublicKeyString() string {
	publicKeyString := []byte(ReadFile(os.Getenv("ACCESS_PUBLIC_PEM_FILE")))

	return string(publicKeyString)
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Public Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaAccessPublicKey() (*ecdsa.PublicKey, error) {
	publicKey := []byte(ReadFile(os.Getenv("ACCESS_PUBLIC_PEM_FILE")))
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Refresh
   |--------------------------------------------------------------------------
*/
func EcdsaRefreshPublicKey() (*ecdsa.PublicKey, error) {
	publicKey := []byte(ReadFile(os.Getenv("REFRESH_PUBLIC_PEM_FILE")))
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaAccessPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey := []byte(ReadFile(os.Getenv("ACCESS_PRIVATE_PEM_FILE")))
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaRefreshPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey := []byte(ReadFile(os.Getenv("REFRESH_PRIVATE_PEM_FILE")))
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)

	return key, err
}
