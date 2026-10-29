# CITIZEN · Open source distribution

This package contains the workshop canvas and central session administration.
Released under the MIT License; see [LICENSE.md](LICENSE.md).

## Publish the canvas on GitHub Pages

Commit the entire package at the root of your public repository, including the
.github/ directory. In the repository's Settings → Pages → Build and deployment,
set Source to GitHub Actions. Push to main, or run **Deploy canvas demo to GitHub
Pages** manually from the Actions tab on main.

The included workflow publishes the contents of dist/ directly. It does not need
to install dependencies or build the app. Drawing, local saves and session
import/export work on Pages; central administration requires the server below.

## Start the server

Install Node.js 22 or newer. In this directory, run:

```sh
npm install --omit=dev
npm start
```

Open http://127.0.0.1:3000 for the canvas and
http://127.0.0.1:3000/admin.html for administration. Complete administrator setup
on the server computer with a display name and a password of at least 12 characters.

Set HOST=0.0.0.0 for LAN access and PORT to change the default port (3000).
In PowerShell, use `$env:HOST = "0.0.0.0"` before `npm start`.
Use HTTPS outside a trusted local network; set CITIZEN_SECURE_COOKIES=1 for HTTPS.

Create a collection in Admin, then use Join Group on each workshop device with
the collection code. Admin can review, export, import and restore backed-up sessions.
Use Export ZIP to keep portable workshop backups.

## Data and administrator recovery

Browser sessions save locally in IndexedDB. Central backups and credentials live
in data/ inside this package. Stop the server before copying data/ for a full backup.
CITIZEN_DATA_DIR or CITIZEN_DATABASE can select another storage location.
Keep your data directory outside the distribution when replacing it with a newer build.
To reset a forgotten administrator password locally, stop the server and run
`npm run admin:reset` with the same data settings, then restart.

The dist/ HTML, assets and public pages can also be served by a static host for local-only
canvas use. Central administration and backups require the Node.js server.
Publish the contents of dist/ directly to GitHub Pages or another static host;
relative asset and navigation paths support repository URLs as well as domain roots.
When the server is absent, Admin and Join Group explain the server requirement.
Drawing, overlays, browser saves and session import/export remain available.
Third-party notices are in [third-party-notices.txt](dist/third-party-notices.txt).
