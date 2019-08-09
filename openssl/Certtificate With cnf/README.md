genrsa -out euge_old.key 2048
pkcs8 -topk8 -nocrypt -in euge_old.key -out euge.key
req -new -key euge.key -out euge.pem -config conf.cnf -reqexts v3_req
x509 -req -days 3650 -in euge.pem -signkey euge.key -out euge.pem -extfile conf.cnf -extensions v3_ca
pkcs12 -export -in euge.pem -inkey euge.key -out euge.pfx
rsa -in euge.key -pubout
keytool -printcert -file .\euge.pem