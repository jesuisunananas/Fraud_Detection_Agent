import os
import json
import time
import random
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from google import genai
from google.genai import types
import asyncio
import sqlite3
import logging
import re
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

load_dotenv()
GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")
client=genai.Client()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
os.makedirs('evidence', exist_ok=True)

CRYPTO_PATTERNS = {
    "BTC_Legacy": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "BTC_Segwit": re.compile(r'\bbc1[ac-hj-np-z02-9]{6,87}\b', re.IGNORECASE),
    "ETH/ERC-20": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "TRC-20": re.compile(r'\bT[A-Za-z1-9]{33}\b'),
    "XMR": re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
}

class Action(BaseModel):
    type: str = Field(description="The action type: 'click', 'fill', or 'none'")
    target: Optional[str] = Field(description="Playwright selector. MUST use :has-text('...') instead of :contains('...').")
    value: Optional[str] = Field(description="The text to type if the action is 'fill'")

class ScamAnalysis(BaseModel):
    classification: str = Field(description="'scam' or 'not scam'")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    found_addresses: List[str] = Field(description="List of raw cryptocurrency addresses found on the page")
    requires_action: bool = Field(description="True if clicking 'Login', 'Deposit', etc., might reveal addresses")
    action: Optional[Action] = Field(description="The specific action to perform if requires_action is true")
    reasoning: str = Field(description="Brief explanation of why this is/isn't a scam and why the action was chosen")

def get_db_connection():
    """Creates a fresh connection with WAL mode for concurrency."""
    conn = sqlite3.connect('scans.db', timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            url TEXT PRIMARY KEY,
            status TEXT DEFAULT 'PENDING', -- PENDING, PROCESSING, COMPLETED, FAILED, DEAD
            retry_count INTEGER DEFAULT 0,
            is_scam BOOLEAN,
            addresses TEXT, -- Store as JSON string
            reasoning TEXT,
            confidence REAL
        )
    ''')
    conn.commit()
    conn.close()

def seed_db_from_file(filepath="urls.txt"):
    """Reads URLs from a file and inserts them into the database if they don't exist."""
    if not os.path.exists(filepath):
        logging.warning(f"{filepath} not found. Make sure to provide the URL list.")
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    with open(filepath, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    added_count = 0
    for url in urls:
        try:
            cursor.execute('INSERT OR IGNORE INTO urls (url, status) VALUES (?, ?)', (url, 'PENDING'))
            if cursor.rowcount > 0:
                added_count += 1
        except Exception as e:
            print(f"Error inserting {url}: {e}")
            
    conn.commit()
    conn.close()
    logging.info(f"Seeded database with {added_count} new URLs.")

def update_db_status(url, status, is_scam=None, addresses=None, reasoning=None, confidence=None, retry_count=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if status == 'COMPLETED':
        addr_json = json.dumps(addresses) if addresses else "[]"
        cursor.execute('''
            UPDATE urls SET status = ?, is_scam = ?, addresses = ?, reasoning = ?, confidence = ? WHERE url = ?
        ''', (status, is_scam, addr_json, reasoning, confidence, url))
    elif retry_count is not None:
        cursor.execute('UPDATE urls SET status = ?, retry_count = ? WHERE url = ?', (status, retry_count, url))
    else:
        cursor.execute('UPDATE urls SET status = ? WHERE url = ?', (status, url))
        
    conn.commit()
    conn.close()

def extract_addresses_from_text(text: str) -> List[Dict[str, str]]:
    found = []
    seen = set()
    for chain, pattern in CRYPTO_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            addr = match if isinstance(match, str) else match[0]
            if addr not in seen:
                seen.add(addr)
                found.append({"chain": chain, "address": addr})
    return found

async def extract_from_dom(page):
    """Deep extraction: Pulls addresses from hidden data attributes and clipboard buttons."""
    addresses = []
    try:
        elements = await page.query_selector_all('[data-address], [data-wallet], [data-to]')
        for el in elements:
            for attr in ['data-address', 'data-wallet', 'data-to']:
                val = await el.get_attribute(attr)
                if val: addresses.append(val)
                
        copy_buttons = await page.query_selector_all('[onclick*="copy"], [data-clipboard-text]')
        for btn in copy_buttons:
            val = await btn.get_attribute('data-clipboard-text')
            if val: addresses.append(val)
    except Exception as e:
        logging.debug(f"DOM extraction error: {e}")
    return addresses

async def dismiss_overlays(page):
    selectors = [
        "button:has-text('Accept')", "button:has-text('Continue')",
        "button:has-text('Close')", "[aria-label='Close']", ".modal-close", "button:has-text('I Agree')"
    ]
    for sel in selectors:
        try:
            await page.click(sel, timeout=1000, force=True)
        except:
            pass

async def scan_network_response(response, address_list):
    try:
        if response.request.resource_type in ['fetch', 'xhr', 'document']:
            body = await asyncio.wait_for(response.text(), timeout=2.0)
            if body:
                found = extract_addresses_from_text(body)
                address_list.extend(found)
    except Exception:
        pass

async def analyze_page_with_gemini(page, url, retries=3):
    screenshot_bytes = await page.screenshot(type='jpeg', quality=80, full_page=False)
    try:
        page_text = await page.inner_text("body", timeout=5000)
    except Exception:
        page_text = ""
    truncated_text = page_text[:15000] 

    prompt = f"""
    Analyze {url} for crypto scams (fake exchanges, phishing, investment scams).
    Classify it, extract ANY visible crypto addresses, and decide if a login/deposit button needs to be clicked.
    Page Text: {truncated_text}
    """

    for attempt in range(retries):
        try:
            response = await client.aio.models.generate_content(
                model='gemini-2.5-flash',
                contents=[types.Part.from_bytes(data=screenshot_bytes, mime_type='image/jpeg'), prompt],
                config=types.GenerateContentConfig(response_mime_type="application/json", response_schema=ScamAnalysis, temperature=0.0)
            )
            return json.loads(response.text)
        except Exception as e:
            if "429" in str(e) or "quota" in str(e).lower():
                wait = (2 ** attempt) * 10
                logging.warning(f"[{url}] API Rate limited. Backing off for {wait}s...")
                await asyncio.sleep(wait)
            else:
                logging.error(f"[{url}] Gemini API Error: {e}")
                return None
    return None

def generate_output_json():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT url, is_scam, addresses, reasoning, confidence, status FROM urls WHERE status != 'PENDING'")
    
    results = []
    for row in cursor.fetchall():
        url, is_scam, addresses_str, reasoning, confidence, status = row
        classification = "scam" if is_scam else "not scam"
        if status in ('DEAD', 'FAILED') and is_scam is None:
            classification = "not scam"
            reasoning = f"Analysis failed. Status: {status}"
            
        extracted_addresses = json.loads(addresses_str) if addresses_str and addresses_str != "[]" else []
        results.append({
            "url": url,
            "classification": classification,
            "confidence": confidence if confidence is not None else 0.0,
            "extracted_addresses": extracted_addresses,
            "reasoning": reasoning or ""
        })
        
    with open('output.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    conn.close()
    logging.info("Successfully generated output.json!")

async def process_url(url, browser_context):
    context = await browser_context.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        viewport={"width": 1280, "height": 800}
    )
    page = await context.new_page()
    final_classification = "not scam"
    final_reasoning = ""
    final_confidence = 0.0
    all_found_addresses = []
    network_tasks = []
    screenshot_taken = False

    page.on("response", lambda r: network_tasks.append(
        asyncio.create_task(scan_network_response(r, all_found_addresses))
    ) if len(network_tasks) < 100 else None)
    try:
        logging.info(f"Navigating to {url}")
        await page.goto(url, timeout=20000, wait_until='domcontentloaded')

        await dismiss_overlays(page)

        for depth in range(3):
            await asyncio.sleep(random.uniform(2.0, 4.0))
            print(f"[{url}] --- Agent Step {depth + 1} ---")
            analysis = await analyze_page_with_gemini(page, url)
            if not analysis:
                break

            raw_html = await page.content()
            try:
                inner_text = await page.inner_text("body", timeout=5000)
            except Exception:
                inner_text = ""

            found_by_regex = extract_addresses_from_text(raw_html + " " + inner_text)
            #all_found_addresses.extend(found_by_regex)

            dom_addrs = await extract_from_dom(page)
            gemini_addrs = analysis.get('found_addresses', [])
            gemini_validated = extract_addresses_from_text(" ".join(gemini_addrs))
            new_addresses_found = len(found_by_regex) > 0 or len(dom_addrs) > 0 or len(gemini_validated) > 0

            if new_addresses_found and not screenshot_taken:
                safe_filename = url.replace("https://", "").replace("/", "_")
                await page.screenshot(path=f"evidence/{safe_filename}.png", full_page=True)
                screenshot_taken = True
                logging.info(f"[{url}] Contextual screenshot captured with visible address!")
            all_found_addresses.extend(found_by_regex)
            all_found_addresses.extend(gemini_validated)
            if dom_addrs:
                all_found_addresses.extend([{"chain": "UNKNOWN", "address": a} for a in dom_addrs])

            if analysis.get('classification') == 'scam':
                final_classification = 'scam'
                final_confidence = max(final_confidence, analysis.get('confidence', 0.0))
            elif final_classification != 'scam':
                final_confidence = analysis.get('confidence', 0.0)
            final_reasoning += " " + analysis.get('reasoning', '')
            action = analysis.get('action')

            if analysis.get('requires_action') and action and action.get('type') != 'none':
                print(f"[{url}] Action required: {action['type']} on '{action.get('target')}'")
                target = action.get('target', '')
                target = target.replace(':contains', ':has-text')
                try:
                    if action['type'] == 'click':
                        await page.click(target, timeout=5000, force=True)
                    elif action['type'] == 'fill':
                        await page.fill(target, action.get('value', ''), timeout=5000)
                    
                    try:
                        await page.wait_for_load_state('domcontentloaded', timeout=5000)
                    except PlaywrightTimeoutError:
                        pass
                except Exception as e:
                    logging.debug(f"[{url}] Action failed: {e}")
                    break
            else:
                break

        if network_tasks:
            done, pending = await asyncio.wait(network_tasks, timeout=5.0)
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        unique_addresses = {json.dumps(d, sort_keys=True) for d in all_found_addresses}
        final_addresses = [json.loads(d) for d in unique_addresses]

        return True, {
            "is_scam": True if final_classification == 'scam' else False,
            "addresses": final_addresses,
            "reasoning": final_reasoning.strip(),
            "confidence": final_confidence
        }
    except PlaywrightTimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    finally:
        await context.close()

async def main_loop():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT url, retry_count FROM urls WHERE status='PENDING' OR (status='FAILED' AND retry_count < 3)")
    pending_urls = cursor.fetchall()
    conn.close()

    if not pending_urls:
        logging.info("End of DB. Generating Report.")
        generate_output_json()
        return
    
    semaphore = asyncio.Semaphore(5)
    
    async def bounded_process(url, retries, browser):
        async with semaphore:
            if retries > 0:
                await asyncio.sleep(5 * retries)

            update_db_status(url, 'PROCESSING')
            success, result = await process_url(url, browser)

            if success:
                update_db_status(
                    url=url, 
                    status='COMPLETED', 
                    is_scam=result['is_scam'], 
                    addresses=result['addresses'], 
                    reasoning=result['reasoning'],
                    confidence=result.get('confidence', 0.0)
                )
                logging.info(f"[{url}] SUCCESS | Scam: {result['is_scam']} | Addrs: {len(result['addresses'])} | Conf: {result.get('confidence')}")
            else:
                new_retries = retries + 1
                if new_retries >= 3:
                    update_db_status(url, 'DEAD', retry_count=new_retries)
                    logging.warning(f"[{url}] MARKED DEAD: {result}")
                else:
                    update_db_status(url, 'FAILED', retry_count=new_retries)
                    logging.warning(f"[{url}] FAILED (Retry {new_retries}): {result}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        tasks = [bounded_process(url, retries, browser) for url, retries in pending_urls]
        await asyncio.gather(*tasks)
        await browser.close()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM urls WHERE status='FAILED' AND retry_count < 3")
    remaining = cursor.fetchone()[0]
    conn.close()

    if remaining > 0:
        logging.info(f"{remaining} URLs need retry. Re-running...")
        await main_loop()  # Only recurse if there's actual work to do
    else:
        generate_output_json()


if __name__ == "__main__":
    init_db()
    seed_db_from_file("urls.txt")
    asyncio.run(main_loop())