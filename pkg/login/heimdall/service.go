// Package service provides the implementation of various service functions for user authorization and tag assignment.

package heimdall

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/org"
)

var (
	logger = log.New("dataos.heimdall")
	admin  = false
)

type BasicUserInfo struct {
	Id             string
	Name           string
	Email          string
	Login          string
	Role           org.RoleType
	OrgRoles       map[int64]org.RoleType
	IsGrafanaAdmin *bool // nil will avoid overriding user's set server admin setting
	Groups         []string
}

type AuthorizationRequest struct {
	Token   string                       `json:"token"`
	Context *AuthorizationRequestContext `json:"context,omitempty"`
}

type AuthorizationRequestContext struct {
	Predicate string        `json:"predicate"`
	Object    ContextObject `json:"object"`
}

type ContextObject struct {
	Tags []string `json:"Tags,omitempty"`
}

type AuthorizationResponse struct {
	Allow  bool                `json:"allow,omitempty" binding:"required"`
	Result AuthorizationResult `json:"result,omitempty"`
	Error  interface{}         `json:"error,omitempty"`
}

type AuthorizationResult struct {
	ID   string      `json:"id"`
	Data interface{} `json:"data,omitempty"`
	Tags []string    `json:"tags,omitempty"`
}

const (
	ContentType = "application/json"
)

type Config struct {
	HeimdallBaseUrlKey string `env:"HEIMDALL_URL" envDefault:"https://heimdall-api.heimdall.svc.cluster.local:32010/heimdall"`
	AuthorizePath      string `env:"HEIMDALL_AUTH_URL" envDefault:"/api/v1/authorize"`
	HeimdallUseUnsafe  string `env:"HEIMDALL_USE_UNSAFE" envDefault:"true"`
}

var Tags = []string{"dataos:type:grafana:admin", "dataos:type:grafana:view"}

func checkAuthorization(accessToken string, tag string) (*AuthorizationResponse, error) {

	myClient := client()

	cfg, err := LoadConfig()
	if err != nil {
		fmt.Printf("failed to load environment variables")
	}

	aR := AuthorizationRequest{
		Token: accessToken,
		Context: &AuthorizationRequestContext{
			Predicate: "get",
			Object: ContextObject{
				Tags: []string{tag},
			},
		},
	}

	req, err := json.Marshal(aR)

	if err != nil {
		fmt.Printf("Error marshaling JSON:")
	}
	authReq := bytes.NewReader(req)

	response, err := myClient.Post(cfg.HeimdallBaseUrlKey+cfg.AuthorizePath, ContentType, authReq)
	if err != nil {
		fmt.Printf("Not able to reach heimdall")
	}

	var ar AuthorizationResponse
	responseContent, err := io.ReadAll(response.Body)
	json.Unmarshal(responseContent, &ar)

	return &ar, nil
}

func AuthorizeUser(token string, userInfo *BasicUserInfo) (*BasicUserInfo, error) {

	for _, tag := range Tags {
		ar, err := checkAuthorization(token, tag)
		if err != nil {
			return nil, err
		}
		if ar.Allow {
			if tag == Tags[0] {
				admin = true
				userInfo.Role = org.RoleAdmin
				userInfo.IsGrafanaAdmin = &admin
				return userInfo, nil
			} else if tag == Tags[1] {
				userInfo.Role = org.RoleViewer
				admin = false
				userInfo.IsGrafanaAdmin = &admin
			}
		} else {
			userInfo.Role = org.RoleNone
			admin = false
			userInfo.IsGrafanaAdmin = &admin
		}
	}

	return userInfo, nil
}

// client configures an HTTP client with TLS verification disabled.
func client() *http.Client {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Printf("failed to load environment variables")
	}
	if cfg.HeimdallUseUnsafe == "true" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{Timeout: 10 * time.Second, Transport: tr}
	} else if cfg.HeimdallUseUnsafe == "false" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		}
		return &http.Client{Timeout: 10 * time.Second, Transport: tr}
	} else {
		fmt.Println("Value of HEIMDALL_USE_UNSAFE is neither true nor false")
		return nil
	}
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
