# Running

```shell
$ go run main.go
```

Call the endpoints in a different shell or with a browser.

This will generate its own RSA and Elliptic private keys, then serialize and deserialize them just to make sure that works.

It will return a token from either of the token endpoints. Feel free to use https://jwt.io to verify.