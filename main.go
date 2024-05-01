package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

var rsaPrivateKey *rsa.PrivateKey
var ellipticPrivateKey *ecdsa.PrivateKey
var counter uint64
var counterMutex sync.RWMutex

func getAndIncrementCounter() uint64 {
	counterMutex.Lock()
	defer counterMutex.Unlock()
	temp := counter
	counter++
	return temp
}

func main() {
	buildAndPrintRSAKey()
	buildAndPrintEllipticKey()
	log.Println("Listening on :8080 with endpoints GET /jwks.json, GET /token-RS256, and GET /token-EC")

	http.HandleFunc("/jwks.json", jwksHandler)
	http.HandleFunc("/token-RS256", rs256_tokenHandler)
	http.HandleFunc("/token-EC", ec_tokenHandler)

	log.Panic(
		http.ListenAndServe(":8080", nil),
	)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	rsaKey := jose.JSONWebKey{
		Key:       &rsaPrivateKey.PublicKey,
		KeyID:     "kid1",
		Algorithm: "RS256",
	}
	ecKey := jose.JSONWebKey{
		Key:       &ellipticPrivateKey.PublicKey,
		KeyID:     "kid2",
		Algorithm: "ES256",
	}
	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			rsaKey.Public(),
			ecKey.Public(),
		},
	}

	bytes, err := json.Marshal(set)
	if err != nil {
		_, _ = fmt.Fprintf(w, "INTERNAL ERROR: %s", err)
	}
	_, _ = fmt.Fprint(w, string(bytes))
}

func buildAndPrintRSAKey() {
	bitSize := 4096

	tempKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatalf("failed to generate RSA private key: %s", err)
	}

	privateBytes, err := x509.MarshalPKCS8PrivateKey(tempKey)
	if err != nil {
		log.Fatalf("failed to marshal private key: %s", err)
	}

	publicBytes := x509.MarshalPKCS1PublicKey(&tempKey.PublicKey)

	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateBytes,
		},
	)

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		log.Fatal("failed to decode PEM block")
	}

	maybeRSAPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("x509.ParsePKCS1PrivateKey failure: %s", err)
	}
	var ok bool
	rsaPrivateKey, ok = maybeRSAPrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("key is not an RSA private key")
	}

	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicBytes,
		},
	)

	log.Printf("RSA private key:\n%s", string(privatePEM))
	log.Printf("RSA public key:\n%s", string(publicPEM))
}

func buildAndPrintEllipticKey() {
	tempPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ECDSA private key: %s", err)
	}

	pkcs8PrivateKeyBytes, err := x509.MarshalPKCS8PrivateKey(tempPrivateKey)
	if err != nil {
		log.Fatalf("x509.MarshalPKCS8PrivateKey failure: %s", err)
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(&tempPrivateKey.PublicKey)
	if err != nil {
		log.Fatalf("x509.MarshalPKIXPublicKey failure: %s", err)
	}

	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: pkcs8PrivateKeyBytes,
		},
	)

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		log.Fatal("failed to decode PEM block")
	}

	maybeEllipticPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("x509.ParseECPrivateKey failure: %s", err)
	}

	var ok bool
	ellipticPrivateKey, ok = maybeEllipticPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("key is not an EC private key")
	}

	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		},
	)

	log.Printf("elliptic private key:\n%s", string(privatePEM))
	log.Printf("elliptic public key:\n%s", string(publicPEM))
}

func rs256_tokenHandler(w http.ResponseWriter, _ *http.Request) {
	mapClaims := jwt.MapClaims{
		"token-number": fmt.Sprintf("%d", getAndIncrementCounter()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	signedString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		_, _ = fmt.Fprintf(w, "INTERNAL ERROR: %s", err)
	}
	_, _ = fmt.Fprint(w, signedString)

	compact, err := jose.ParseSignedCompact(signedString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		log.Fatalf("failed to parse signed compact: %s", err)
	}

	_, err = compact.Verify(&rsaPrivateKey.PublicKey)
	if err != nil {
		log.Fatalf("unable to verify signature: %s", err)
	}
}

func ec_tokenHandler(w http.ResponseWriter, _ *http.Request) {
	mapClaims := jwt.MapClaims{
		"token-number": fmt.Sprintf("%d", getAndIncrementCounter()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, mapClaims)
	signedString, err := token.SignedString(ellipticPrivateKey)
	if err != nil {
		_, _ = fmt.Fprintf(w, "INTERNAL ERROR: %s", err)
	}
	_, _ = fmt.Fprint(w, signedString)

	compact, err := jose.ParseSignedCompact(signedString, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		log.Fatalf("failed to parse signed compact: %s", err)
	}

	_, err = compact.Verify(&ellipticPrivateKey.PublicKey)
	if err != nil {
		log.Fatalf("unable to verify signature: %s", err)
	}
}
