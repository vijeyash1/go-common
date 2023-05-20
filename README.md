# go-common
To keep common libraries used in go based microservices

## logging
common logging package to write the logs in common format

## vault
vault client to read the service user credential and user certificates
- supports authenticating vault using kubernetes role or vault token
- service user credentail reader client provide method to read services user credentials
- service user credentail admin client provide methods to read/put/delete services user credentials
- client certificate admin client provide methods to read/put/delete client certificates