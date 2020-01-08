# Create Certificate

## Create Private Key - pair

```sh
genrsa -out tmoen1_old.key 2048
pkcs8 -topk8 -nocrypt -in tmoen1_old.key -out tmoen1.key
```

## Create csr

```sh
req -new -key tmoen1.key -out tmoen1.csr -config conf.cnf -reqexts v3_req
```

## Sign the csr

```sh
x509 -req -days 3650 -in tmoen1.csr -signkey tmoen1.key -out tmoen1.pem -extfile conf.cnf -extensions v3_ca
```

## Create pfk format

```sh
pkcs12 -export -in tmoen1.pem -inkey tmoen1.key -out tmoen1.pfx
```



# Checks

## Show public key

```sh
rsa -in tmoen1.key -pubout
```

## Show certificate

```sh
keytool -printcert -file .\tmoen1.pem
```