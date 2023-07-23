package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/nnhutan/goplock/initializers"
)

type GoogleOauthToken struct {
	Access_token string
	Id_token     string
}

type GoogleUserResult struct {
	Id             string
	Email          string
	Verified_email bool
	Name           string
	Given_name     string
	Family_name    string
	Picture        string
	Locale         string
}

func GetGoogleOauthToken(code string) (*GoogleOauthToken, error) {
	const rootURl = "https://oauth2.googleapis.com/token"

	// code=4%2F0AZEOvhUFcrnD7tiCRL9icik1EFFbSoRBS3QqujHXfiyVyTA9dM2ZJPTV5qZyF8toADjWuw&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=407343280800-4rje1o7ud0c5vn28kk16q6lqniih820e.apps.googleusercontent.com&client_secret=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&scope=&grant_type=authorization_code
	config, _ := initializers.LoadConfig(".")
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", config.GoogleClientID)
	values.Add("client_secret", config.GoogleClientSecret)
	values.Add("redirect_uri", "https://developers.google.com/oauthplayground") // => use for testing

	query := values.Encode()

	req, err := http.NewRequest("POST", rootURl, bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		log.Println(bodyString)
		return nil, errors.New("Could not retrieve token")
	}

	var resBody bytes.Buffer
	_, err = io.Copy(&resBody, res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleOauthTokenRes map[string]interface{}

	if err := json.Unmarshal(resBody.Bytes(), &GoogleOauthTokenRes); err != nil {
		return nil, err
	}

	tokenBody := &GoogleOauthToken{
		Access_token: GoogleOauthTokenRes["access_token"].(string),
		Id_token:     GoogleOauthTokenRes["id_token"].(string),
	}

	return tokenBody, nil
}

func GetGoogleUser(access_token string, id_token string) (*GoogleUserResult, error) {
	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", access_token)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id_token))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("Could not retrieve user")
	}

	var resBody bytes.Buffer
	_, err = io.Copy(&resBody, res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes map[string]interface{}

	if err := json.Unmarshal(resBody.Bytes(), &GoogleUserRes); err != nil {
		return nil, err
	}

	userBody := &GoogleUserResult{
		Id:             GoogleUserRes["id"].(string),
		Email:          GoogleUserRes["email"].(string),
		Verified_email: GoogleUserRes["verified_email"].(bool),
		Name:           GoogleUserRes["name"].(string),
		Given_name:     GoogleUserRes["given_name"].(string),
		Picture:        GoogleUserRes["picture"].(string),
		Locale:         GoogleUserRes["locale"].(string),
	}

	return userBody, nil
}
