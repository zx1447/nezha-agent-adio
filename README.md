# nezha-agent (Adios deploy)

Pure Node.js supervised Nezha agent for free PaaS platforms.
All credentials are injected via environment variables:

- `NZ_SERVER` - panel address, e.g. `panel.example.com:443`
- `NZ_TLS` - `true`/`false`
- `NZ_CLIENT_SECRET` - panel agent secret
- `NZ_UUID` - optional static server uuid
- `PORT` - status page port

`start.js` writes `/tmp/config.yml`, launches `nezha-agent`, restarts on crash,
serves a status page (and `/health`) on `$PORT`.
