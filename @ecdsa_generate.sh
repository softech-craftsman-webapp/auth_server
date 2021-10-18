mkdir -p keys
mkdir -p keys/access
mkdir -p keys/refresh
# ES256 => prime256v1
# ES384 => secp384r1
# ES512 => secp521r1

# @AccessToken
# private key
openssl ecparam -genkey -name prime256v1 -noout -out keys/access/private.pem
# public key
openssl ec -in keys/access/private.pem -pubout -out keys/access/public.pem

# @RefreshToken
# private key
openssl ecparam -genkey -name prime256v1 -noout -out keys/refresh/private.pem
# public key
openssl ec -in keys/refresh/private.pem -pubout -out keys/refresh/public.pem 