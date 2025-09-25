package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGeneratePasswordHash(t *testing.T) {
	cases := make(map[string]error)
	cases["pass"] = nil
	cases["otherpass"] = nil
	cases["something827"] = nil
	cases["bogoas*D7vsnlk"] = nil

	for k, v := range cases {
		h, err := HashPassword(k)
		if err != v {
			t.Fail()
		}
		err = CheckPassHash(k, h)
		if err != v {
			t.Fail()
		}
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	type testUser struct {
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
	}
	cases := []testUser{
		{
			userID:      uuid.New(),
			tokenSecret: "Pass1234",
			expiresIn:   1 * time.Second,
		},
		{
			userID:      uuid.New(),
			tokenSecret: "coolPassword",
			expiresIn:   5 * time.Minute,
		},
		{
			userID:      uuid.New(),
			tokenSecret: "CowboyBebopisthebestanimeeveryoneshouldwatchitandloveitlikeido",
			expiresIn:   5 * time.Second,
		},
	}

	for i := range cases {
		tS, err := MakeJWT(cases[i].userID, cases[i].tokenSecret, cases[i].expiresIn)
		if err != nil {
			t.Fail()
		}
		id, err := ValidateJWT(tS, cases[i].tokenSecret)
		if err != nil {
			t.Fail()
			fmt.Printf("Error: %s\n", err)
		}
		if id != cases[i].userID {
			t.Fail()
		}
	}

	for i := range cases {
		_, err := ValidateJWT("This should fail!", cases[i].tokenSecret)
		if err == nil {
			t.Fail()
		}
	}
}

func TestGetBearerToken(t *testing.T) {
	h := make(http.Header, 1)
	h["Authorization"] = []string{"Bearer JWTtoken"}

	s, err := GetBearerToken(h)
	if err != nil {
		t.Fail()
	}
	if s != "JWTtoken" {
		t.Fail()
	}

	h["Authorization"] = []string{"This should fail"}
	_, err = GetBearerToken(h)
	if err == nil {
		t.Fail()
	}
}
