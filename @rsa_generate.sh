mkdir -p keys
mkdir -p keys/access
mkdir -p keys/refresh
# RS256 => SHA256
# RS384 => SHA384
# RS512 => SHA512

# @AccessToken
# private key
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f keys/access/rsa-private.pem
# public key
openssl rsa -in keys/access/rsa-private.pem -pubout -outform PEM -out keys/access/rsa-public.pem

# @RefreshToken
# private key
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f keys/refresh/rsa-private.pem
# public key
openssl rsa -in keys/refresh/rsa-private.pem -pubout -outform PEM -out keys/refresh/rsa-public.pem