# BeatFund PWA setup

## Generate icons
Run the icon generator from the repo root:

```bash
python tools/generate_icons.py
```

This reads `static/brand/BeatFund_IconOnly_TightRounded.svg` and writes PNGs to:
- `static/img/favicon/icon-192.png`
- `static/img/favicon/icon-512.png`
- `static/img/favicon/icon-180.png`
- `static/img/favicon/icon-32.png`
- `static/img/favicon/icon-16.png`

## Local testing (Chrome)
1) Run the Flask app.
2) Open Chrome DevTools → Application.
3) Check **Manifest** and **Service Workers** sections.
4) Verify the install prompt and icons.

## Install steps
- Android (Chrome): Tap the install prompt or “Install app” from the menu.
- iOS (Safari): Share -> Add to Home Screen.
- Desktop (Chrome/Edge): Use the install icon in the address bar or the “Install BeatFund” button.

## Troubleshooting
- If changes don’t appear, do a hard refresh and/or unregister the service worker.
- After updating the service worker, close all tabs and reopen the site.
- Ensure HTTPS is used in production.

## Manual checklist
- [ ] Manifest loads with correct fields and icons.
- [ ] Service worker is registered and active.
- [ ] Install button appears on supported browsers.
- [ ] iOS install tip appears on Safari.
- [ ] Offline page appears when offline.
