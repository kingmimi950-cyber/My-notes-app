# Fieldnotes

A private journal with your own account, synced across devices, markdown formatting,
photo attachments, per-entry encryption, a calendar view, and a light/dark theme.

## What's in here

```
fieldnotes-app/
  server/         Node.js + Express backend (SQLite database, JWT auth, file uploads)
  public/         Frontend (plain HTML/CSS/JS — no build step)
```

Everything is self-hosted: your entries live in a SQLite file on your own server, not
on someone else's cloud.

## 1. Requirements

- Node.js 18 or newer ([nodejs.org](https://nodejs.org))

## 2. Setup

```bash
cd server
npm install
cp .env.example .env
```

Open `.env` and set `JWT_SECRET` to a long random string. You can generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## 3. Run it

```bash
cd server
npm start
```

Then open **http://localhost:3001** in your browser. Create an account (this is stored
only on your own server) and you're in.

To use it from your phone or another computer on the same network, replace `localhost`
with your computer's local IP address (e.g. `http://192.168.1.20:3001`).

## 4. Putting it online (so it syncs anywhere)

Any Node-friendly host works — Render, Railway, Fly.io, a DigitalOcean droplet, etc.
The general steps are the same everywhere:

1. Push this folder to a Git repository (the `.gitignore` already excludes your local
   database and uploads).
2. Create a new service pointing at the `server/` folder, with the start command
   `npm install && npm start`.
3. Set the `JWT_SECRET` environment variable in the host's dashboard (same value idea
   as your local `.env`, just don't reuse the literal example value).
4. Note that the SQLite database (`server/fieldnotes.db`) and uploaded photos
   (`server/uploads/`) are files on disk. Most free hosting tiers wipe local disk on
   redeploy — for anything long-term, either pick a host with a persistent volume/disk,
   or swap SQLite for a hosted database later if you outgrow this.
5. Once deployed, visit your host's URL from any device to use the same account.

## How the features work

**Sync** — every entry is stored server-side and fetched over a REST API, so signing
in from a new device shows the same journal.

**Markdown** — the "Write / Preview" toggle above each entry renders standard markdown
(headings, lists, links, images, code blocks) using `marked`, sanitized with
`DOMPurify` before display.

**Photos** — the "Photo" button uploads an image to your server (`server/uploads/`)
and adds it to the entry as an attachment thumbnail; it's also insertable inline via
markdown image syntax if you paste the returned URL into the text.

**Lock / encryption** — locking an entry encrypts its title and body in your browser
with AES-GCM before it's ever sent to the server, using a key derived (PBKDF2) from a
passphrase you set. The server only ever stores ciphertext for locked entries — it
never sees your passphrase or the plaintext. This also means:
- If you forget the passphrase, that content is **not recoverable** — there's no reset.
- The passphrase lives only in your browser's memory for the current session; you'll
  be asked for it again after a page reload.
- Tags and dates stay unencrypted (so filtering and the calendar still work); only the
  title and body are hidden.

**Calendar** — click the calendar icon to see a month grid with a dot on any day you
wrote something; click a day to filter the list down to it.

**Theme** — the sun/moon icon switches between light and dark, saved per-browser.

## Security notes

This is a solid starting point, not a hardened production deployment. Before relying
on it for anything sensitive over the open internet, you'd want to:
- Serve it over HTTPS (most hosts listed above do this for you automatically).
- Consider rate-limiting the login/register endpoints.
- Keep the `JWT_SECRET` private and rotate it if it's ever exposed.
