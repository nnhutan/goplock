package utils

import (
	"context"
	"fmt"
	"time"

	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nnhutan/goplock/initializers"
)

type TokenDetails struct {
	Token     *string
	TokenUuid string
	UserID    string
	ExpiresIn *int64
}

func CreateToken(userId string, ttl time.Duration, privateKey string) (*TokenDetails, error) {
	now := time.Now().UTC()
	td := &TokenDetails{
		ExpiresIn: new(int64),
		Token:     new(string),
	}
	*td.ExpiresIn = now.Add(ttl).Unix()
	td.TokenUuid = uuid.New().String()
	td.UserID = userId

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode token private key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)

	if err != nil {
		return nil, fmt.Errorf("create: parse token private key: %w", err)
	}

	atClaims := make(jwt.MapClaims)
	atClaims["sub"] = userId
	atClaims["token_uuid"] = td.TokenUuid
	atClaims["exp"] = td.ExpiresIn
	atClaims["iat"] = now.Unix()
	atClaims["nbf"] = now.Unix()

	*td.Token, err = jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims).SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("create: sign token: %w", err)
	}

	return td, nil
}

func ValidateToken(token string, publicKey string) (*TokenDetails, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)

	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}

	return &TokenDetails{
		TokenUuid: fmt.Sprint(claims["token_uuid"]),
		UserID:    fmt.Sprint(claims["sub"]),
	}, nil
}

func GenerateTokenPair(userId string, config *initializers.Config) (*TokenDetails, *TokenDetails, error) {
	redisClient := initializers.RedisClient

	accessTokenDetails, err := CreateToken(userId, config.AccessTokenExpiresIn, config.AccessTokenPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate token pair: create access token: %w", err)
	}

	refreshTokenDetails, err := CreateToken(userId, config.RefreshTokenExpiresIn, config.RefreshTokenPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate token pair: create refresh token: %w", err)
	}

	ctx := context.TODO()
	now := time.Now()

	errAccess := redisClient.Set(ctx, accessTokenDetails.TokenUuid, userId, time.Unix(*accessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return nil, nil, fmt.Errorf("generate token pair: set access token: %w", errAccess)
	}

	errRefresh := redisClient.Set(ctx, refreshTokenDetails.TokenUuid, userId, time.Unix(*refreshTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errRefresh != nil {
		return nil, nil, fmt.Errorf("generate token pair: set refresh token: %w", errRefresh)
	}

	return accessTokenDetails, refreshTokenDetails, nil
}
