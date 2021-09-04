openssl req \
  -new \
  -x509 \
  -nodes \
  -days 365 \
  -subj '/CN=my-ca' \
  -keyout ca.key \
  -out ca.crt

openssl x509 \
  --in ca.crt \
  -text \
  --noout

openssl genrsa \
  -out server.key 2048


openssl req \
  -new \
  -key server.key \
  -subj '/CN=localhost' \
  -out server.csr

openssl x509 \
  -req \
  -in server.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -days 365 \
  -out server.crt

openssl x509 \
  --in server.crt \
  -text \
  --noout

openssl genrsa \
  -out client.key 2048

openssl req \
  -new \
  -key client.key \
  -subj '/CN=my-client' \
  -out client.csr

openssl x509 \
  -req \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -days 365 \
  -out client.crt


openssl genrsa \
  -out client2.key 2048

openssl req \
  -new \
  -key client2.key \
  -subj '/CN=my-client' \
  -out client2.csr

openssl x509 \
  -req \
  -in client2.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -days 365 \
  -out client2.crt
