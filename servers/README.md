## Examples

### HTTPS listener using Let's Encrypt, with HTTP->HTTPS redirector & http challenge on :80 for Let's Encrypt
#### This is useful for Cloudflare, Nginx, and other servers in front, because they do not respond to ALPN challenges.

```go
cfg, killChan, err := servers.Start(servers.New(router, logger, servers.WithLetsEncrypt(true, "domain.com")))
if err != nil {
...
}

err = servers.Start(cfg)
```

### HTTPS listener using Let's Encrypt, with HTTP->HTTPS redirector & alpn challenge on :443 for Let's Encrypt

```go
cfg, killChan, err := servers.Start(servers.New(router, logger, servers.WithHTTP(":80"), servers.WithLetsEncrypt(false, "domain.com")))
if err != nil { ... }
err = servers.Start(cfg)
```

### HTTPS listener using Let's Encrypt, with no redirector & alpn challenge on :443 for Let's Encrypt

```go
cfg, killChan, err := servers.New(router, logger, servers.WithLetsEncrypt(false, "domain.com")))
if err != nil { ... }
err = servers.Start(cfg)
```
