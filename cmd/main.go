package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const authAPIEndpoint = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"

var (
	apiKey   string
	email    string
	password string
)

func init() {
	flag.StringVar(&apiKey, "key", os.Getenv("API_KEY"), "Use signInWithPassword api key")
	flag.StringVar(&email, "email", os.Getenv("EMAIL"), "Use signInWithPassword user's email.")
	flag.StringVar(&password, "password", os.Getenv("PASSWORD"), "Use signInWithPassword user's password.")
	flag.Parse()
}

func main() {
	ctx := context.Background()
	payload, err := signInWithPassword(ctx, &signInWithPasswordInput{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	})
	if err != nil {
		fmt.Printf("failed signInWithPassword(). Reason %s\n", err.Error())
		return
	}

	fmt.Printf("Bearer %s", payload.IDToken)
}

type signInWithPasswordInput struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type signInWithPasswordPayload struct {
	Email   string `json:"email"`
	IDToken string `json:"idToken"`
}

type errorPayload struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
			Domain  string `json:"global"`
			Reason  string `json:"invalid"`
		} `json:"errors"`
	} `json:"error"`
}

func signInWithPassword(ctx context.Context, input *signInWithPasswordInput) (*signInWithPasswordPayload, error) {
	reqBodyBytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(reqBodyBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authAPIEndpoint, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	values := req.URL.Query()
	values.Set("key", apiKey)
	req.URL.RawQuery = values.Encode()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp errorPayload
		err = json.Unmarshal(respBodyBytes, &errorResp)
		if err != nil {
			return nil, err
		}

		return nil, errors.New(errorResp.Error.Message)
	}

	var payload signInWithPasswordPayload
	err = json.Unmarshal(respBodyBytes, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil
}
