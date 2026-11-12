# ADR 0010: Nostr login, one-click lots and the world-leader merch catalogue

Status: accepted (approved by the owner 2026-11-12; shipped in v0.5.0, with ADR 0009)

## Context

The demo gives every browser four local characters: Seller, Alice, Bob and Carol. The page switches between them from the bar at the top, and the bots bid as whichever characters you are not. The owner wants to keep this and add:

- **Nostr login.** A logged-in user gets the same fake sats and a wallet, and bids as themselves or as any of the characters.
- **One-click lots.** The user can create a random auction, either fixed time or anti-snipe, then watch it join the line-up and the bots bid on it.
- **A catalogue of generated lots.** All generated lots show Bitcoin merchandise sold by famous world leaders.

## Decision

### Login

- **"Log in with Nostr"** sits in the identity bar.
  - It uses **NIP-07** (a browser extension such as Alby or nos2x) when `window.nostr` is present.
  - Otherwise it uses **NIP-46** (a remote signer such as Amber on Android). The user pastes a `bunker://` URI or scans a `nostrconnect://` QR code. The relay comes from that URI, so the site adds no relay of its own.
- **Only events are signed with the login key:** listing (1440), bid (1441) and chat (1442). The validators already check event signatures by pubkey, so the chain does not change.
- **The wallet key stays local.** NIP-07 and NIP-46 sign events only, not Cashu lock messages. A logged-in user therefore gets a browser wallet key and Coco seed, saved under their npub in IndexedDB. Refunds and payouts (ADR 0009) lock to this key. Logging out keeps the wallet for the next login on the same browser.
- **Fake sats:** the same faucet and auto top-up as the characters.
- **Profile (logged-in users only):** after login, the page fetches the user's profile (kind 0) and shows their name and picture. It never fetches profiles for the characters or for other bidders.
  - **Which relays.** The page first fetches the user's relay list (NIP-65, kind 10002) from:
    - `wss://relay.chiefmonkey.art` (the operator's own relay);
    - the relays the signer reports (NIP-07 `getRelays()` where the extension supports it, or the relay in the NIP-46 URI);
    - two well-known fallbacks, `wss://nos.lol` and `wss://purplepag.es`.

    It then reads kind 0 from the user's own write relays and keeps the newest event.
  - **Bounded.** At most 6 relays are asked, each read has a 4 s timeout, and the connections close once the profile arrives. The relay list is a setting, so an operator can change it.
  - **Cached.** The profile is kept in IndexedDB with the wallet and refreshed at most once an hour.
  - **Shown to others.** The display name goes into the user's bid and listing events (the existing `name` field). Other viewers see the name without fetching anything.
  - **Picture.** The avatar loads straight from the profile's URL with `referrerpolicy="no-referrer"`, shown at 64 px, https only. A broken or non-https image falls back to the initial.
  - **Fallback.** If no profile is found, the page shows the short npub, and the user can type a name.
- **Extension prompts:** the page asks the user to tick "remember this site" once, so each bid is not interrupted. A bid that waits for the signer shows "waiting for your signer" in the pending state (ADR 0006).

### Identity bar

- `You` (with your profile picture and name, or the short npub) appears first, beside Seller, Alice, Bob and Carol. It is shown only when logged in.
- Picking any chip bids as that identity. The bots bid as every chip except the one selected, and never as You.

### One-click lots

- A **"New lot"** menu has two buttons: **Fixed time** and **Anti-snipe**.
- One tap picks a random catalogue item and lists it, with the logged-in user as seller (or the Seller character when not logged in). The new lot appears in the queue at once.
- **Fixed lot:** duration chosen at random from 2–6 min.
- **Anti-snipe lot:** duration 2–6 min, window X from 20 s to 2 min.
- **Start price and increment** come from the catalogue entry.
- Lots are rate-limited per identity on the page (one per 30 s) and by the chain's existing limits.
- `seedIfEmpty()` uses the same catalogue, with a mix of both modes, so the arena is never empty.

### Catalogue

- About 24 entries, each with a title, description, category, price, increment and image.
- Each entry has the seller name set to a famous world leader, present or past, selling Bitcoin merchandise. Examples: hoodies, mugs, signed node boxes, laser-eyes portraits, hardware wallets, "stacking sats" banners.
- **Labelled as parody.** Every lot card and the outcome screen say "Parody · fake sats". Images show the product only, never a photo or likeness of a real person.
- **Images:** generated once and bundled as small WebP files (target under 60 KB each, under 1.5 MB in total). They are served from the same site, so there are no external image requests.

## Consequences

- **Good:**
  - Real Nostr identities can use the demo.
  - The characters and bots stay.
  - Anyone can make a lot in one tap and watch it trade.
- **Cost:**
  - `nostr-tools` NIP-46 support adds to the bundle (about 15–25 KB gzipped; measured in the PR).
  - The image set adds about 1.5 MB, loaded lazily per lot.
- **Risk:**
  - Real names are used as parody sellers. The parody label is on every lot, and no likenesses are used.
  - A browser wallet tied to an npub is only on that browser. Clearing site data loses the fake sats; the faucet refills them.

## Tests

- **NIP-07:** a mock `window.nostr` signs a bid, and the validators accept it under that pubkey.
- **NIP-46:** a mock remote signer (in-process relay in the test) does the same.
- **Profile:** with a mock relay that serves a relay list and a kind 0 event, the page shows the name and picture and puts the name into the user's bids. With no relay answering, it falls back to the short npub within 4 s.
- **Wallet survives logout:** log out and back in on the same browser, and the balance is still there.
- **One-click lots:**
  - "Fixed time" and "Anti-snipe" each create a lot of the right mode;
  - the bots bid on it;
  - it settles by push (ADR 0009).
- **Catalogue:** every entry passes the chain's listing checks (title, image path, price ranges).

## As built (v0.5.0)

- **Leaders of the past only.** The catalogue has 24 entries, all historical leaders (from Ramesses II to Ronald Reagan). No living leader is used, to keep the parody clearly a joke.
- **Images:** 16 product-only studio photos (generated, no people, no faces, no logos), 640 × 640 WebP, 10–38 KB each, 362 KB in total. On a parody lot the seller chip shows the product, not a face.
- **NIP-46:** `bunker://` links and `nostrconnect://` links (relays `wss://relay.chiefmonkey.art` and `wss://nos.lol`, shown as a link and as copyable text; no QR image). NIP-05 names (`name@domain`) are not resolved, because the page's CSP allows no fetches to other sites. The NIP-46 code is loaded only when used (36 KB, 12 KB gzipped).
- **Profile cache:** kept in `localStorage` with the login, refreshed at most once an hour; IndexedDB is used for the wallet only. Simpler, and the profile is a few hundred bytes.
- **CSP:** the Suite's policy for the auctions site adds `connect-src wss:` (relays) and `img-src https:` (profile pictures). Scripts, styles, fonts and workers stay same-site.
- **Tests:** `web/test/login.mjs` covers remote signing (a wrong-key answer is refused), the profile reader against a stand-in relay (signature check, write relays from kind 10002, wss only, at most 6 relays, name cleaned and capped, https-only picture) and the catalogue against the chain's listing rules. The UI was checked in headless Chromium with a stand-in NIP-07 extension: log in, You chip, one-click anti-snipe lot, bidding against the bots, pushed refunds.

