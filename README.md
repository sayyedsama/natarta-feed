# Natarta scam feed

This repo holds the public, free data feed for the Natarta app. It contains only the feed builders; the app source is private.

- `feed/` builds the **Local Scam Alerts** feed from official public RSS: FBI IC3, US DOJ, CISA, FTC and selected local government feeds (see `feed/sources.json` for each source's license and terms notes). It republishes only headlines and short summaries, each with a link back to the original.
- `scripts/update-blocklist.mjs` turns the [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) phishing-domain list (MIT, © Mitchell Krog, Nissar Chababy & contributors) into a hashed rule pack.
- `feed/ftc-phones.mjs` turns the [FTC robocall complaint dataset](https://github.com/usacallerlookup/ftc-robocall-dataset) (CC0 aggregation of public-domain FTC Do Not Call and NANPA data) into a compact signed lookup, `ftc-phones.json`. Phones download the whole file and look numbers up on the device; no number is ever sent anywhere.
- `feed/crypto-scams.mjs` turns the [MetaMask eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) blacklist (DBAD "Don't Be A Dick" public license, © 2018 kumavis) into a signed, hashed lookup, `crypto-scams.json` (~110k fake crypto and wallet sites). Phones check sites on the device. ScamSniffer's scam-database is not used (GPL-3.0).
- `feed/more-scam-sites.mjs` builds `more-scam-sites.json` (~250k scam and phishing sites, signed, hashed, matched on the phone) from the [CERT Polska Warning List](https://cert.pl/en/warning-list/) (free for any use, including commercial; rebuilt every run so domains CERT Polska removes drop out; naming it does not mean CERT Polska endorses Natarta) and [The Block List Project](https://github.com/blocklistproject/Lists) phishing and scam lists (Unlicense / MIT). The ~20,000 most-linked sites are never shipped. ThreatFox/URLhaus (abuse.ch) are not used: downloads need a signed-in key and for-profit use may need their paid API.
- GitHub Actions rebuilds them every 3 hours and publishes them to GitHub Pages. Every feed file is signed with Ed25519.

No personal data is collected. Phones download their area's file anonymously.
