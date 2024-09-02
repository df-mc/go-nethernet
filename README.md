# go-nethernet

An implementation of NetherNet, the new transport layer introduced in Minecraft: Bedrock Edition based on WebRTC written in Go.

## Getting started

### Using a fork of pion/sctp

Because Mojang seems to have made several changes to their dcSCTP implementation, you need to use a fork of pion/sctp.

To use the fork, put the following (for example) `replace` directive in go.mod of your main module and run ``go mod tidy``.

``replace github.com/pion/sctp => github.com/lactyy/sctp latest``

This workaround is planned to be removed in future release.