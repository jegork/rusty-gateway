# Changelog

## [0.3.0](https://github.com/jegork/rusty-gateway/compare/v0.2.0...v0.3.0) (2026-09-11)


### Features

* daily wal checkpoint for the audit and state databases ([947a4fc](https://github.com/jegork/rusty-gateway/commit/947a4fcb014606af7a0ffeb5c4998dcba6e0750b))
* re-authorize oauth upstreams from the dashboard and the login endpoint ([f7d13e5](https://github.com/jegork/rusty-gateway/commit/f7d13e5fbc4a58f97fb7042b7023ef5e19cf84da))


### Bug Fixes

* advertise offline_access so clients obtain refresh tokens ([ab757f4](https://github.com/jegork/rusty-gateway/commit/ab757f40d83ec6cc8d51b6d01d38557b37c462d0))
* sign dashboard sessions so they survive redeploys ([e7782c9](https://github.com/jegork/rusty-gateway/commit/e7782c9896902d96921219699bdfbd64484aab79))

## [0.2.0](https://github.com/jegork/rusty-gateway/compare/v0.1.0...v0.2.0) (2026-09-08)


### Features

* capture upstream stderr as structured log records with per-server level ([b4fc08e](https://github.com/jegork/rusty-gateway/commit/b4fc08efafb0cced5e429d0bdb1014b91faf46ec))
* concurrency limits, call timeouts, circuit breaker, remote http upstreams ([0ff8d18](https://github.com/jegork/rusty-gateway/commit/0ff8d186b38d5e766f709019b0cb7840f7ac89d8))
* connector and search tool discovery modes per namespace ([e112964](https://github.com/jegork/rusty-gateway/commit/e1129648aa7c80cc57142974b93889559a992c10))
* datastar dashboard with live upstream status, tool browser and audit log ([f041b5e](https://github.com/jegork/rusty-gateway/commit/f041b5ee161bb77db779a2e215374361851c0edd))
* log session initialize with client info regardless of initialized notification ([56b6690](https://github.com/jegork/rusty-gateway/commit/56b66904ddf4108a22da81d0beace298b3c4f3d1))
* oauth login, token persistence and refresh for remote upstreams ([29c68a4](https://github.com/jegork/rusty-gateway/commit/29c68a4f916099645211446f47fed10fb2d8aa19))
* per-namespace protected resource metadata and audience validation ([8e0ff4e](https://github.com/jegork/rusty-gateway/commit/8e0ff4e992630d50656d458d8dbbb74adf1f4517))
* prefix tool titles with the server name ([c9e5fd2](https://github.com/jegork/rusty-gateway/commit/c9e5fd29cd47b27280df0aa9a18d750eef9be4bb))
* ship node and uv runtimes in the image, add compose file and healthcheck ([f9f66a8](https://github.com/jegork/rusty-gateway/commit/f9f66a8d6a158576184b7942c1b4106e3c492441))
* start upstream oauth logins on boot and log the url to open ([6569f9b](https://github.com/jegork/rusty-gateway/commit/6569f9bd25f559f3dc03b8e29ce4a1d237dbee92))


### Bug Fixes

* default data_dir next to the audit db and name the path in open errors ([5912476](https://github.com/jegork/rusty-gateway/commit/59124765be446ab654f46ca714a5a33570c48b04))
* do not block startup on upstreams that need an oauth login ([e1f126d](https://github.com/jegork/rusty-gateway/commit/e1f126dace980ae681e13d1633a4025558156f4c))
* include line, column and context in toml parse errors ([09c5724](https://github.com/jegork/rusty-gateway/commit/09c572418fc109fad3e6b60dfce80a439e31f77f))
* keep upstreams that answer ping with method not found alive ([021caf6](https://github.com/jegork/rusty-gateway/commit/021caf64e71a8a87a06efcdd32a8a5bdf5b5ab83))
* mount namespace handlers by name so per-namespace routes resolve ([1a3def9](https://github.com/jegork/rusty-gateway/commit/1a3def9efa50cbc6301fb05464e76fdde93b84b4))
* never send ping on 2026-07-28 sessions, where the method no longer exists ([ab7d207](https://github.com/jegork/rusty-gateway/commit/ab7d20787a75c69a18d21ea610e82e0cf65c6089))
* read scopes from scp array claim as issued by fosite-based servers ([69ddfbf](https://github.com/jegork/rusty-gateway/commit/69ddfbfba4d8314f2d0b6e51ac8e56f4719a63aa))
* remember servers that reject ping across sessions and add a ping config switch ([3a07f70](https://github.com/jegork/rusty-gateway/commit/3a07f70ef915d5ed2d82f6b4749cf5cf787d16a4))
* resolve bare upstream commands through PATH at load ([df3df1e](https://github.com/jegork/rusty-gateway/commit/df3df1eef87cad03b5e03236d0779be0c7fb1943))
* send the 2026-07-28 _meta envelope on health pings ([9d76660](https://github.com/jegork/rusty-gateway/commit/9d766608b4e8db66c14bc63afe110e7c171b917a))
* stay quiet when auto-login is interrupted by shutdown ([7e81fae](https://github.com/jegork/rusty-gateway/commit/7e81fae83de97a228e81e83b95ba5d76b9b9e8fc))
* stop health pings for sessions whose server rejects the first ping ([37deb54](https://github.com/jegork/rusty-gateway/commit/37deb54d4e268f01b3316e655224d038e823403f))
* stop logging the bearer-protected login endpoint as if it were the browser url ([be69821](https://github.com/jegork/rusty-gateway/commit/be69821bab23cf2297bba55982d97bbc9ba6ec0d))

## 0.1.0 (2026-09-07)


### Features

* redacted sqlite audit log with read api and tail command ([0109469](https://github.com/jegork/rusty-gateway/commit/0109469a2c0b54a680221ebba0076fd5092e0932))
* report per-upstream rss in healthz and add dockerfile ([640baea](https://github.com/jegork/rusty-gateway/commit/640baea6650e576a163070bb29e88c8558c395c3))
* supervised stdio mcp aggregator with namespaces and bearer auth ([530479b](https://github.com/jegork/rusty-gateway/commit/530479b63f0e4a9fed946f55fd0f8e64711e2cac))

## Changelog
