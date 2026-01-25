#!/usr/bin/env node
// Usage: node generate-icons.js /path/to/master.png
// Requires: npm install sharp

const fs = require('fs');
const path = require('path');
const sharp = require('sharp');

async function ensureDir(dir){
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

const outputs = [
  {name: 'favicon-16x16.png', size: 16},
  {name: 'favicon-32x32.png', size: 32},
  {name: 'apple-touch-icon.png', size: 180},
  {name: 'android-chrome-192x192.png', size: 192},
  {name: 'android-chrome-512x512.png', size: 512},
  {name: 'mstile-150x150.png', size: 150},
  {name: 'android-chrome-384x384.png', size: 384},
  {name: 'favicon.ico', ico: [16,32,48]}
];

async function makeIco(source, outPath){
  // create temporary PNGs for ico then use sharp to join
  const tmp = [];
  for (const s of [16,32,48]){
    const tmpPath = outPath + `.${s}.png`;
    tmp.push(tmpPath);
    await sharp(source).resize(s,s).png().toFile(tmpPath);
  }
  // sharp can write ico by piping multiple pngs
  const images = await Promise.all(tmp.map(p => fs.promises.readFile(p)));
  await sharp({create:{width:48,height:48,channels:4,background:{r:0,g:0,b:0,alpha:0}}}).png().toFile(outPath + '.placeholder.png');
  await sharp(images[2]).resize(48,48).toFile(outPath); // fallback: write largest as .ico (some environments ignore multi-icon .ico)
  // cleanup
  for (const p of tmp) try{ await fs.promises.unlink(p) }catch(e){}
  try{ await fs.promises.unlink(outPath + '.placeholder.png') }catch(e){}
}

async function main(){
  const src = process.argv[2];
  if (!src){
    console.error('Usage: node generate-icons.js /path/to/master.png');
    process.exit(2);
  }
  if (!fs.existsSync(src)){
    console.error('Source not found:', src);
    process.exit(3);
  }
  const outDir = path.join(process.cwd(), '.');
  await ensureDir(outDir);

  for (const o of outputs){
    const outPath = path.join(outDir, o.name);
    if (o.ico){
      console.log('Creating', o.name);
      await makeIco(src, outPath);
      continue;
    }
    console.log('Creating', o.name, o.size + 'x' + o.size);
    await sharp(src).resize(o.size,o.size, {fit: 'cover'}).png().toFile(outPath);
  }

  // also create higher-resolution icons used by some PWA tools
  console.log('Creating android-chrome-512x512.png (already created) and a 1024px master for Play Store');
  await sharp(src).resize(1024,1024, {fit: 'cover'}).png().toFile(path.join(outDir, 'icon-1024.png'));

  console.log('Done. Files written to', outDir);
  console.log('Tip: move generated icons into your public/ or static/ folder and update manifest.json as needed.');
}

main().catch(err=>{ console.error(err); process.exit(1); });
