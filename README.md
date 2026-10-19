# Kiite

A small macOS menu-bar app. Drop a file onto the kite, upload it to your SFTP server, and copy its public link.

## Install

Requires Xcode command-line tools and [Homebrew](https://brew.sh).

```sh
brew install libssh2 openssl@3
git clone https://github.com/iSach/kiite.git
cd kiite
make install
open /Applications/Kiite.app
```

In Settings, choose your SSH key, trust your server's host key, and enter the public directory, a separate private staging directory, and its HTTPS base URL. Short URLs and start at login are optional.

`make test` runs local checks and an isolated SFTP integration test. MIT licensed.
