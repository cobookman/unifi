package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
)

type Unifi struct {
	user     string
	password string
	url      string
	site     string
	version  string
	cookie   string
	client   *http.Client
	loggedin bool
}

var (
	ErrNotLoggedIn         error = errors.New("Not logged in")
	ErrLoginBadCredentials error = errors.New("Bad Login Credentials")
	ErrLoginUnkown         error = errors.New("Unknown issue with login")
	ErrAuthGuestUnknown    error = errors.New("Error authenticating guest")
)

func NewClient(user, password, url, site, version string, insecure bool) *Unifi {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	cj, _ := cookiejar.New(nil)

	return &Unifi{
		user:     user,
		password: password,
		url:      url,
		site:     site,
		version:  version,
		client: &http.Client{
			Transport: tr,
			Jar:       cj,
		},
		loggedin: false,
	}
}

func (u Unifi) api(path string, json []byte) (*http.Response, error) {
	return u.client.Post(u.url+path, "application/json; charset=utf-8", bytes.NewReader(json))
}

func (u *Unifi) Login() error {
	// if cookie set, skip login
	if len(u.cookie) != 0 {
		return nil
	}

	type payloadLogin struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	l := payloadLogin{
		Username: u.user,
		Password: u.password,
	}

	j, err := json.Marshal(l)
	if err != nil {
		return err
	}

	// b := bytes.NewReader(j)
	resp, err := u.api("/api/login", j)
	// resp, err := u.client.Post(u.url+"/api/login", "application/json", b)
	if err != nil {
		return err
	}

	if resp.StatusCode == 400 {
		return ErrLoginBadCredentials
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(ErrLoginUnkown, body)

		return ErrLoginUnkown
	}

	u.loggedin = true
	return nil
}

type UnifiGuest struct {
	Mac     string `json:"mac"`     // client MAC address
	Expires int    `json:"minutes"` // number of minutes from now to remove access
	Up      int    `json:"up"`      //upload speed limit (Kibps)
	Down    int    `json:"down"`    // donwload speed limit  (Kibs)
	Data    int    `json:"data"`    // max data transfer "data cap" for session (MiB)
}

func (u *Unifi) AuthGuest(g UnifiGuest) error {
	if !u.loggedin {
		return ErrNotLoggedIn
	}

	type payloadAuthGuest struct {
		Cmd string `json:"cmd"`
		UnifiGuest
	}

	p := payloadAuthGuest{}
	p.Cmd = "authorize-guest"
	p.Mac = g.Mac
	p.Expires = g.Expires
	p.Up = g.Up
	p.Down = g.Down
	p.Data = g.Data

	j, err := json.Marshal(p)
	log.Print(string(j))
	if err != nil {
		return err
	}

	resp, err := u.api("/api/s/"+u.site+"/cmd/stamgr", j)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(ErrLoginUnkown, string(body))

		return ErrAuthGuestUnknown
	}

	return nil
}
