// Package endpoint implements NetherNet signaling over HTTP: a Handler serving the '/v1/join'
// endpoint that clients use to join a server by address, and a Client that dials one.
//
// # How clients find the endpoint
//
// A client joining host:port first sends 'GET <base>/v1/join' to these base URLs, unless a URL
// already worked for the same host and port:
//
//   - port 19132 or no port: https://host:19132, https://host, http://host:19132, http://host
//   - any other port: https://host:port, http://host:port
//
// The https URLs are requested together. The http URLs follow once every https request has
// finished. The first 2xx response wins and is remembered for later joins. If none answers
// within about six seconds, the client joins over RakNet instead.
//
// Every probed port should answer or refuse quickly. A port that silently drops packets holds
// back the http URLs until that limit. HTTPS with a certificate the client trusts, on the game
// port or on 443, is the fastest path and avoids the trust prompt shown for plain HTTP.
package endpoint
