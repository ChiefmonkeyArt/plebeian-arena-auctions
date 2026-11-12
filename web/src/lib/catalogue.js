// Parody catalogue (ADR 0010): Bitcoin merchandise "sold" by famous leaders
// of the past. Every lot is labelled "Parody · fake sats"; the images show
// the product only, never a person. Bundled WebP files, same site.
const img = (n) => `./assets/merch/${n}.webp`;

export const CATALOGUE = [
  { name: 'Winston Churchill', title: '"Never Sell" stacking sats banner, wartime print', description: 'Heavy cotton, brass grommets. We shall stack on the beaches.', category: 'Banners', image: img('banner'), startPrice: 2100, minIncrement: 100 },
  { name: 'Abraham Lincoln', title: 'Log-cabin oak node box, honestly synced', description: 'Hand-split oak case, 2 TB, fully validated from the genesis block.', category: 'Nodes', image: img('nodebox'), startPrice: 5000, minIncrement: 250 },
  { name: 'Queen Victoria', title: 'Royal-crest "21 Million" porcelain mug', description: 'We are not amused by inflation. Dishwasher safe.', category: 'Mugs', image: img('mug'), startPrice: 800, minIncrement: 50 },
  { name: 'Napoleon Bonaparte', title: 'Campaign hoodie: "Short on fiat, long on sats"', description: 'Imperial orange, fleece lined. Runs small.', category: 'Hoodies', image: img('hoodie'), startPrice: 1500, minIncrement: 100 },
  { name: 'Julius Caesar', title: 'Laurel-gold physical bitcoin: "Veni, vidi, HODLi"', description: 'Brass, 40 mm, struck for the Ides of March halving.', category: 'Coins', image: img('coin'), startPrice: 1200, minIncrement: 100 },
  { name: 'Cleopatra', title: 'Hieroglyph hardware wallet, lapis edition', description: 'Air-gapped. Seed words in plain English, not hieroglyphs.', category: 'Wallets', image: img('hwwallet'), startPrice: 3000, minIncrement: 150 },
  { name: 'George Washington', title: '"I cannot tell a lie, I run a node" desk clock', description: 'Cherry wood. Ticks once per block, roughly.', category: 'Clocks', image: img('clock'), startPrice: 1800, minIncrement: 100 },
  { name: 'Theodore Roosevelt', title: 'Rough Rider cap: "Speak softly, carry a seed phrase"', description: 'Orange twill, embroidered B. One size.', category: 'Caps', image: img('cap'), startPrice: 600, minIncrement: 50 },
  { name: 'Franklin D. Roosevelt', title: '"The only thing to fear is fiat" fireside mug', description: 'Stoneware, holds one long fireside chat of coffee.', category: 'Mugs', image: img('mug'), startPrice: 700, minIncrement: 50 },
  { name: 'Margaret Thatcher', title: 'Iron Lady steel seed plate, 24 words', description: 'Stainless steel, fire and flood tested. The plate is not for turning.', category: 'Wallets', image: img('steelplate'), startPrice: 2500, minIncrement: 150 },
  { name: 'Elizabeth I', title: 'Golden Age laser-eyes lion portrait', description: 'Oil on canvas print, gilt frame, 40 × 50 cm.', category: 'Art', image: img('portrait'), startPrice: 4000, minIncrement: 200 },
  { name: 'Charlemagne', title: 'Holy Roman sticker pack, 21 stickers', description: 'Vinyl, weatherproof. Unites most of Europe on one laptop lid.', category: 'Stickers', image: img('stickers'), startPrice: 300, minIncrement: 25 },
  { name: 'Peter the Great', title: "Tsar's winter scarf in Bitcoin orange", description: 'Merino, 2 m. Built for a long bear market.', category: 'Scarves', image: img('scarf'), startPrice: 900, minIncrement: 50 },
  { name: 'Catherine the Great', title: 'Hermitage tote: "Stack like an empress"', description: 'Canvas, inside pocket for a hardware wallet.', category: 'Bags', image: img('tote'), startPrice: 500, minIncrement: 25 },
  { name: 'John F. Kennedy', title: '"Ask not what your node can do for you" T-shirt', description: 'Organic cotton, navy, orange print.', category: 'T-shirts', image: img('tshirt'), startPrice: 700, minIncrement: 50 },
  { name: 'Ronald Reagan', title: '"Tear down this paywall" sats socks', description: 'Two pairs, orange heel, lightning toe.', category: 'Socks', image: img('socks'), startPrice: 400, minIncrement: 25 },
  { name: 'Charles de Gaulle', title: '"Vive le bloc" tricolour stacking banner', description: 'Silk-screened. 246 varieties of cheese, one supply cap.', category: 'Banners', image: img('banner'), startPrice: 1900, minIncrement: 100 },
  { name: 'Otto von Bismarck', title: 'Realpolitik running shoes, 21 eyelets', description: 'Iron soles, orange laces. Moves at block speed.', category: 'Shoes', image: img('sneakers'), startPrice: 2200, minIncrement: 100 },
  { name: 'Simón Bolívar', title: 'Liberator laser-eyes condor portrait', description: 'Giclée print on cotton rag, 30 × 40 cm.', category: 'Art', image: img('portrait'), startPrice: 3500, minIncrement: 200 },
  { name: 'Ramesses II', title: 'Pyramid-free physical bitcoin, sandstone finish', description: 'The only pyramid here is on the box.', category: 'Coins', image: img('coin'), startPrice: 1100, minIncrement: 100 },
  { name: 'Alexander the Great', title: 'Conqueror hoodie: "21 million, not one more"', description: 'Heavyweight, orange drawstrings. No worlds left to conquer, just sats.', category: 'Hoodies', image: img('hoodie'), startPrice: 1600, minIncrement: 100 },
  { name: 'Genghis Khan', title: 'Steppe-tested hardware wallet, horsehide pouch', description: 'Survived 8,000 km on horseback. PIN not included.', category: 'Wallets', image: img('hwwallet'), startPrice: 2800, minIncrement: 150 },
  { name: 'Thomas Jefferson', title: 'Declaration of Independence-from-banks clock', description: 'Walnut, quartz movement, counts down to the next halving.', category: 'Clocks', image: img('clock'), startPrice: 1700, minIncrement: 100 },
  { name: 'Augustus', title: 'Pax Bitcoina node box, marble effect', description: 'Found Rome brick, left it a full node. 2 TB SSD.', category: 'Nodes', image: img('nodebox'), startPrice: 4800, minIncrement: 250 },
];

export const PARODY = 'Parody · fake sats';

const pick = (a) => a[Math.floor(Math.random() * a.length)];
const between = (lo, hi, step = 1) => lo + step * Math.floor(Math.random() * ((hi - lo) / step + 1));

// A random lot of the given mode. Fixed: 2-6 min. Anti-snipe: 2-6 min with
// a window of 20 s to 2 min (ADR 0010).
export function randomLot(mode, item = pick(CATALOGUE)) {
  const lot = { title: item.title, description: item.description, image: item.image, category: item.category,
    startPrice: item.startPrice, minIncrement: item.minIncrement, durationSec: between(120, 360, 30), mode, name: item.name };
  if (mode === 'antisnipe') lot.windowSec = between(20, 120, 10);
  return lot;
}
