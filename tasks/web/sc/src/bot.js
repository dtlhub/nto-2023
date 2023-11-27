import puppeteer from 'puppeteer'

const puppeter_args = {
  headless: 'old',
  args: [
    '--no-sandbox',
    '--user-data-dir=/tmp/chrome-userdata',
    '--breakpad-dump-location=/tmp/chrome-crashes',
    '--block-new-web-contents',
    '--disable-popup-blocking=false',
    '--enable-features=StrictOriginIsolation'
  ]
};

const VISIT_TIMEOUT = 3000

const browser = await puppeteer.launch(puppeter_args);
const sleep = d => new Promise(r => setTimeout(r, d));

export default async function visit(url) {
  const context = await browser.createIncognitoBrowserContext();
  let page = await context.newPage({ ignoreSSL: true });

  await page.goto(url, { ignoreSSL: true })
  await page.evaluate(() => document.documentElement.innerHTML);

  await sleep(VISIT_TIMEOUT)
}
