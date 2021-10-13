mkdir -p keys
mkdir -p keys/access
mkdir -p keys/refresh
# RS256 => SHA256
# RS384 => SHA384
# RS512 => SHA512

# @AccessToken
# private key
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f keys/access/private.pem
# public key
openssl rsa -in keys/access/private.pem -pubout -outform PEM -out keys/access/public.pem

# @RefreshToken
# private key
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f keys/refresh/private.pem
# public key
openssl rsa -in keys/refresh/private.pem -pubout -outform PEM -out keys/refresh/public.pem