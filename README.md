# Webmin Login Proxy

This Webmin login proxy handles the authentication for users, so they don't need to know the actual Webmin password. It acts as a credential broker proxy, simplifying the login process.

## Quick start
Download the latest version at https://github.com/borderzero/webmin-login-proxy/releases 

run `tar -xvzf webmin-login-proxy_0.0.3_linux_amd64.tar.gz`  to untar the files. 

update `config.json` to provide the webmin url and credentials. After that run `./webmin-login-proxy` and you're ready!

```
./webmin-login-proxy
2024/07/01 18:00:19 Starting proxy server on 127.0.0.1:8443
```

## Features

- **Credential Management**: Manages Webmin credentials and handles login on behalf of users.
- **Session Handling**: Creates and manages sessions for authenticated users.
- **Reverse Proxy**: Forwards requests to the Webmin server while managing authentication.

## Warning

**Security Warning:** This proxy effectively opens up your Webmin to anyone on the internet. It is highly recommended to place this proxy behind an authenticating proxy like [Border0](https://border0.com) or another authentication mechanism to secure access. 
It's also recommended to have the Proxy listen on localhost only.

## Usage

### Configuration

Create a `config.json` file with the following structure:

```json
{
  "webminURL": "https://your-webmin-url:10000",
  "listenAddr": "127.0.0.1:8443",
  "username": "your-webmin-username",
  "password": "your-webmin-password",
  "requireBorder0": true

}
```

### Creating PEM Files
When the proxy starts, it will look for the TLS pem files, if they don't exist, the proxy will generate them.
To create `cert.pem` and `key.pem` files manually for SSL/TLS, you can use the following OpenSSL commands:
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
```
Follow the prompts to enter information about your organization. These files are necessary for HTTPS.


### Running the Proxy
* Ensure you have cert.pem and key.pem for SSL/TLS.
* Run the proxy:
```bash
go run main.go
```

The proxy server will start and listen on the address specified in `config.json`.

### Example config.json
```json
{
  "webminURL": "https://your-webmin-url:10000",
  "listenAddr": "127.0.0.1:8443",
  "username": "your-webmin-username",
  "password": "your-webmin-password",
  "requireBorder0": true
}
```
requireBorder0 will make sure only connections through border0 are allowed to be proxied.

 ## Download

Download the latest release [here](https://github.com/borderzero/webmin-login-proxy/releases/latest).



