package nethernet

import "github.com/pion/webrtc/v4"

type Credentials struct {
	ExpirationInSeconds int         `json:"ExpirationInSeconds"`
	ICEServers          []ICEServer `json:"TurnAuthServers"`
}

type ICEServer struct {
	Username string   `json:"Username"`
	Password string   `json:"Password"`
	URLs     []string `json:"Urls"`
}

// gatherOptions transforms Credentials into [webrtc.ICEGatherOptions].
func gatherOptions(credentials *Credentials) (opts webrtc.ICEGatherOptions) {
	if credentials != nil && len(credentials.ICEServers) > 0 {
		opts.ICEServers = make([]webrtc.ICEServer, len(credentials.ICEServers))
		for i, server := range credentials.ICEServers {
			opts.ICEServers[i] = webrtc.ICEServer{
				Username:       server.Username,
				Credential:     server.Password,
				CredentialType: webrtc.ICECredentialTypePassword,
				URLs:           server.URLs,
			}
		}
	}
	return opts
}
