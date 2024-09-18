package nethernet

import "github.com/pion/webrtc/v4"

// Credentials holds the configuration for ICE servers used for gathering local ICE candidates.
type Credentials struct {
	ExpirationInSeconds int         `json:"ExpirationInSeconds"`
	ICEServers          []ICEServer `json:"TurnAuthServers"`
}

// ICEServer represents a single ICE server configuration, including its authentication details
// and connection URLs. Each server requires a username and password for authentication.
type ICEServer struct {
	Username string   `json:"Username"`
	Password string   `json:"Password"`
	URLs     []string `json:"Urls"`
}

// gatherOptions transforms the given Credentials into a [webrtc.ICEGatherOptions] for gathering
// local ICE candidates with [webrtc.ICEGatherer]. If the given credentials are nil or contain no ICE
// servers, it will return a zero value.
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
