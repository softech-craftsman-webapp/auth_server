package crypto

import "github.com/golang-jwt/jwt"

/*
   |--------------------------------------------------------------------------
   | RSA
   |--------------------------------------------------------------------------
*/
// var SigningMethodName = jwt.SigningMethodRS512.Name
// var SigningMethod = jwt.SigningMethodRS512
// var AccessPublicKey = RsaAccessPublicKey
// var AccessPrivateKey = RsaAccessPrivateKey
// var RefreshPublicKey = RsaRefreshPublicKey
// var RefreshPrivateKey = RsaRefreshPrivateKey
// var PublicKeyString = RsaPublicKeyString

/*
   |--------------------------------------------------------------------------
   | ECDSA
   |--------------------------------------------------------------------------
*/
var SigningMethodName = jwt.SigningMethodES256.Name
var SigningMethod = jwt.SigningMethodES256
var AccessPublicKey = EcdsaAccessPublicKey
var AccessPrivateKey = EcdsaAccessPrivateKey
var RefreshPublicKey = EcdsaRefreshPublicKey
var RefreshPrivateKey = EcdsaRefreshPrivateKey
var PublicKeyString = EcdsaPublicKeyString
