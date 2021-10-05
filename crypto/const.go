package crypto

import "github.com/golang-jwt/jwt"

/*
   |--------------------------------------------------------------------------
   | RSA
   |--------------------------------------------------------------------------
*/
var SigningMethodName = jwt.SigningMethodRS512.Name
var SigningMethod = jwt.SigningMethodRS512
var AccessPublicKey = RsaAccessPublicKey
var AccessPrivateKey = RsaAccessPrivateKey
var RefreshPublicKey = RsaRefreshPublicKey
var RefreshPrivateKey = RsaRefreshPrivateKey
var PublicKeyString = RsaPublicKeyString

/*
   |--------------------------------------------------------------------------
   | ECDSA
   |--------------------------------------------------------------------------
*/
// var SigningMethodName = jwt.SigningMethodES512.Name
// var SigningMethod = jwt.SigningMethodES512
// var AccessPublicKey = EcdsaAccessPublicKey
// var AccessPrivateKey = EcdsaAccessPrivateKey
// var RefreshPublicKey = EcdsaRefreshPublicKey
// var RefreshPrivateKey = EcdsaRefreshPrivateKey
// var PublicKeyString = EcdsaPublicKeyString
