package crypto

import (
	"crypto/ecdsa"

	"github.com/golang-jwt/jwt"
)

/*
   |--------------------------------------------------------------------------
   | ECDSA Public Key String
   |--------------------------------------------------------------------------
*/
func EcdsaPublicKeyString() string {
	publicKeyString := []byte(ReadFile("keys/access/ecdsa-public.pem"))

	return string(publicKeyString)
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Public Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaAccessPublicKey() (*ecdsa.PublicKey, error) {
	publicKey := []byte(ReadFile("keys/access/ecdsa-public.pem"))
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Refresh
   |--------------------------------------------------------------------------
*/
func EcdsaRefreshPublicKey() (*ecdsa.PublicKey, error) {
	publicKey := []byte(ReadFile("keys/refresh/ecdsa-public.pem"))
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaAccessPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey := []byte(ReadFile("keys/access/ecdsa-private.pem"))
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | ECDSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func EcdsaRefreshPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey := []byte(ReadFile("keys/refresh/ecdsa-private.pem"))
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)

	return key, err
}
