mkdir -p keys
mkdir -p keys/access
mkdir -p keys/refresh
# ES256 => prime256v1
# ES384 => secp384r1
# ES512 => secp521r1

# @AccessToken
# private key
openssl ecparam -genkey -name secp521r1 -noout -out keys/access/ecdsa-private.pem
# public key
openssl ec -in keys/access/ecdsa-private.pem -pubout -out keys/access/ecdsa-public.pem

# @RefreshToken
# private key
openssl ecparam -genkey -name secp521r1 -noout -out keys/refresh/ecdsa-private.pem
# public key
openssl ec -in keys/refresh/ecdsa-private.pem -pubout -out keys/refresh/ecdsa-public.pem 