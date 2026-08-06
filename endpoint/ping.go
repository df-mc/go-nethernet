package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (c *Client) PingContext(ctx context.Context, address string) (*PongData, error) {
	u, err := parseURL(address)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}
	requestURL := u.JoinPath("/v1/join").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("User-Agent", "libhttpclient/1.0.0.0")

	resp, err := c.conf.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var data *PongData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
		if data == nil {
			return nil, errors.New("nethernet/endpoint: nil ping response")
		}
		return data, nil
	default:
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
	}
}

type PongData struct {
	ServerName     string `json:"name"`
	Protocol       int    `json:"protocol"`
	Version        string `json:"version"`
	LevelName      string `json:"level"`
	PlayerCount    int    `json:"players"`
	MaxPlayerCount int    `json:"maxPlayers"`
	GameType       int    `json:"gameType"`
}

/*
func (d PongData) RakNet() []byte {

}

func RakNetPongData(b []byte) PongData {

}
*/
