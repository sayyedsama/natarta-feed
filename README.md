# Natarta scam feed

This repo holds the public, free data feed for the Natarta app. It contains only the feed builders; the app source is private.

- `feed/` builds the **Local Scam Alerts** feed from official public RSS: FBI IC3, US DOJ, CISA, FTC and selected local government feeds (see `feed/sources.json` for each source's license and terms notes). It republishes only headlines and short summaries, each with a link back to the original.
- `scripts/update-blocklist.mjs` turns the [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) phishing-domain list (MIT, © Mitchell Krog, Nissar Chababy & contributors) into a hashed rule pack.
- GitHub Actions rebuilds both every 3 hours and publishes them to GitHub Pages. Every feed file is signed with Ed25519.

No personal data is collected. Phones download their area's file anonymously.
