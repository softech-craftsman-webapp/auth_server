package crypto

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt"
)

/*
   |--------------------------------------------------------------------------
   | RSA Public Key String
   |--------------------------------------------------------------------------
*/
func RsaPublicKeyString() string {
	publicKeyString := []byte(ReadFile("keys/access/rsa-public.pem"))

	return string(publicKeyString)
}

/*
   |--------------------------------------------------------------------------
   | RSA Public Key @Access
   |--------------------------------------------------------------------------
*/
func RsaAccessPublicKey() (*rsa.PublicKey, error) {
	publicKey := []byte(ReadFile("keys/access/rsa-public.pem"))
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Refresh
   |--------------------------------------------------------------------------
*/
func RsaRefreshPublicKey() (*rsa.PublicKey, error) {
	publicKey := []byte(ReadFile("keys/refresh/rsa-public.pem"))
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func RsaAccessPrivateKey() (*rsa.PrivateKey, error) {
	privateKey := []byte(ReadFile("keys/access/rsa-private.pem"))
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	return key, err
}

/*
   |--------------------------------------------------------------------------
   | RSA Private Key @Access
   |--------------------------------------------------------------------------
*/
func RsaRefreshPrivateKey() (*rsa.PrivateKey, error) {
	privateKey := []byte(ReadFile("keys/refresh/rsa-private.pem"))
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	return key, err
}
