// Package auth implements the hashing funcs for pass
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func CheckPassHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	t := jwt.NewNumericDate(time.Now().UTC())
	e := jwt.NewNumericDate(time.Now().UTC().Add(expiresIn))
	id := uuid.UUID.String(userID)
	c := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  t,
		ExpiresAt: e,
		Subject:   id,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	c := new(jwt.RegisteredClaims)
	token, err := jwt.ParseWithClaims(tokenString, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(tokenSecret), nil
	})
	if err != nil || token == nil || !token.Valid || c.Issuer != "chirpy" {
		return uuid.Nil, fmt.Errorf("invalid token: %w", err)
	}
	return uuid.Parse(c.Subject)
}

func GetBearerToken(h http.Header) (string, error) {
	s, ok := h["Authorization"]
	if !ok {
		return "", fmt.Errorf("error: authorization not found in header")
	}
	if len(s) != 1 {
		return "", fmt.Errorf("error: empty header authorization")
	}
	tS, ok := strings.CutPrefix(s[0], "Bearer ")
	if !ok {
		return "", fmt.Errorf("error: Bearer not found")
	}
	return tS, nil
}

func MakeRefreshToken() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}
