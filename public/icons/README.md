Icon generation helper

Place your master icon (square PNG) somewhere accessible, e.g. the project root as `master.png`.

Prerequisites:
- Node.js (14+)
- npm install sharp

Generate icons:

```powershell
cd public/icons
npm init -y      # if package.json not present
npm i sharp
node generate-icons.js "..\..\master.png"
```

This will produce:
- favicon-16x16.png
- favicon-32x32.png
- apple-touch-icon.png
- android-chrome-192x192.png
- android-chrome-512x512.png
- favicon.ico
- icon-1024.png

Move these into your actual public/static folder if your framework expects a different path, and update `manifest.json` and your `<head>` tags accordingly.
