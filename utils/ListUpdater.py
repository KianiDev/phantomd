import os
import sys
import logging
import requests
import asyncio

from urllib.parse import urlparse


def _write_text(dest_path, text):
    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write(text)


def fetch_blocklists_sync(urls, destination_dir='blocklists'):
    """Fetch blocklists from a list (or comma-separated string) of URLs or local paths synchronously.

    Returns list of (source, True/False) for success of each.
    """
    if isinstance(urls, str):
        # allow comma-separated list
        urls = [u.strip() for u in urls.split(',') if u.strip()]
    os.makedirs(destination_dir, exist_ok=True)
    results = []
    for idx, raw in enumerate(urls):
        raw = raw.strip()
        if not raw:
            continue
        parsed = urlparse(raw)
        # derive filename
        filename = os.path.basename(parsed.path) or f'blocklist_{idx}.txt'
        dest_path = os.path.join(destination_dir, filename)
        try:
            if parsed.scheme in ('http', 'https'):
                resp = requests.get(raw, timeout=30)
                resp.raise_for_status()
                _write_text(dest_path, resp.text)
                results.append((raw, True))
            elif parsed.scheme == '':
                # local file
                if os.path.exists(raw):
                    with open(raw, 'r', encoding='utf-8') as fr, open(dest_path, 'w', encoding='utf-8') as fw:
                        fw.write(fr.read())
                    results.append((raw, True))
                else:
                    results.append((raw, False))
            else:
                results.append((raw, False))
        except Exception as e:
            logging.warning("Failed to fetch %s: %s", raw, e)
            results.append((raw, False))
    return results


async def fetch_blocklists(urls, destination_dir='blocklists'):
    """Async fetch using aiohttp. Returns list of (source, True/False)."""
    try:
        import aiohttp
    except Exception:
        raise RuntimeError("aiohttp is not installed; install aiohttp to use async blocklist fetching")
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split(',') if u.strip()]
    os.makedirs(destination_dir, exist_ok=True)
    results = []
    async with aiohttp.ClientSession() as session:
        for idx, raw in enumerate(urls):
            raw = raw.strip()
            if not raw:
                continue
            parsed = urlparse(raw)
            filename = os.path.basename(parsed.path) or f'blocklist_{idx}.txt'
            dest_path = os.path.join(destination_dir, filename)
            if parsed.scheme in ('http', 'https'):
                try:
                    async with session.get(raw, timeout=30) as resp:
                        resp.raise_for_status()
                        text = await resp.text()
                        _write_text(dest_path, text)
                        results.append((raw, True))

                except Exception as e:
                    logging.warning("Failed to fetch %s: %s", raw, e)
                    results.append((raw, False))
            elif parsed.scheme == '':
                if os.path.exists(raw):
                    try:
                        with open(raw, 'r', encoding='utf-8') as fr, open(dest_path, 'w', encoding='utf-8') as fw:
                            fw.write(fr.read())
                        results.append((raw, True))
                    except Exception as e:
                        logging.warning("Failed to copy local blocklist %s: %s", raw, e)
                        results.append((raw, False))
                else:
                    results.append((raw, False))
            else:
                results.append((raw, False))
    return results


async def periodic_fetch(urls, interval_seconds=86400, destination_dir='blocklists'):
    while True:
        await fetch_blocklists(urls, destination_dir)
        await asyncio.sleep(interval_seconds)


def start_periodic_fetch_in_background(urls, interval_seconds=86400, destination_dir='blocklists'):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # no running loop; fall back to get_event_loop for compatibility
        loop = asyncio.get_event_loop()
    # schedule the coroutine in background
    loop.create_task(periodic_fetch(urls, interval_seconds, destination_dir))


if __name__ == '__main__':
    # quick test
    urls = sys.argv[1:] if len(sys.argv) > 1 else []
    asyncio.run(fetch_blocklists(urls))
