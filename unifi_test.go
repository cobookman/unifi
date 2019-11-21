package unifi

import (
	"os"
	"testing"
)

var (
	// Username for e2e tests
	validUser string = os.Getenv("user")

	// Password for e2e tests
	validPass string = os.Getenv("pass")
)

func TestNewClient(t *testing.T) {
	NewClient(validUser, validPass, "https://192.168.1.1:8443", "default", "5.12.22", true)
}

func TestLogin(t *testing.T) {
	tests := []struct {
		username  string
		password  string
		endpoint  string
		siteId    string
		versionId string
		insecure  bool
		want      error
	}{
		{validUser, validPass, "https://192.168.1.1:8443", "default", "5.12.22", true, nil},
		{validUser, "dog1289", "https://192.168.1.1:8443", "default", "5.12.22", true, ErrLoginBadCredentials},
	}
	for _, tt := range tests {
		u := NewClient(tt.username, tt.password, tt.endpoint, tt.siteId, tt.versionId, tt.insecure)
		err := u.Login()
		if tt.want != err {
			t.Errorf("got %v, want %v", err, tt.want)
		}
	}
}

func TestAuthGuest(t *testing.T) {
	validGuest := UnifiGuest{
		Mac:     "6c:4d:73:cf:0f:7c",
		Expires: 1,
		Up:      1024,
		Down:    1024 * 2,
		Data:    1024 * 10,
	}

	u := NewClient(validUser, validPass, "https://192.168.1.1:8443", "default", "5.12.22", true)
	if err := u.Login(); err != nil {
		t.Error("Failed to login: ", err)
	}

	if err := u.AuthGuest(validGuest); err != nil {
		t.Error("Failed to auth guest: ", err)
	}
}
