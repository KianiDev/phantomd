import os
import sys
import logging
import requests
import asyncio
from typing import List, Optional, Tuple

from urllib.parse import urlparse


def _write_text(dest_path: str, text: str) -> None:
    """Write text content to a file."""
    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write(text)


def fetch_blocklists_sync(
    urls: List[str],
    destination_dir: str = 'blocklists'
) -> List[Tuple[str, bool]]:
    """Fetch blocklists from a list of URLs or local paths synchronously.

    Args:
        urls: A list of URLs (http/https) or local file paths.
        destination_dir: Directory where fetched files are stored.

    Returns:
        A list of (source, success) tuples indicating the fetch result for each source.
    """
    if isinstance(urls, str):
        # allow comma-separated list
        urls = [u.strip() for u in urls.split(',') if u.strip()]
    os.makedirs(destination_dir, exist_ok=True)
    results: List[Tuple[str, bool]] = []
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


async def fetch_blocklists(
    urls: List[str],
    destination_dir: str = 'blocklists'
) -> List[Tuple[str, bool]]:
    """Async fetch using aiohttp. Returns list of (source, True/False)."""
    try:
        import aiohttp
    except Exception:
        raise RuntimeError("aiohttp is not installed; install aiohttp to use async blocklist fetching")
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split(',') if u.strip()]
    os.makedirs(destination_dir, exist_ok=True)
    results: List[Tuple[str, bool]] = []
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


async def periodic_fetch(
    urls: List[str],
    interval_seconds: int = 86400,
    destination_dir: str = 'blocklists'
) -> None:
    """Periodically fetch blocklists at the given interval (seconds)."""
    logging.info("Starting periodic blocklist refresh every %s seconds", interval_seconds)
    while True:
        try:
            await fetch_blocklists(urls, destination_dir)
        except Exception as e:
            logging.warning("Periodic fetch encountered an error: %s", e)
        await asyncio.sleep(interval_seconds)


def start_periodic_fetch_in_background(
    urls: List[str],
    interval_seconds: int = 86400,
    destination_dir: str = 'blocklists'
) -> None:
    """Schedule blocklist fetching as a background task on the current event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # no running loop; fall back to get_event_loop for compatibility
        loop = asyncio.get_event_loop()
    # schedule the coroutine in background
    loop.create_task(periodic_fetch(urls, interval_seconds, destination_dir))


if __name__ == '__main__':
    # quick test
    urls: List[str] = sys.argv[1:] if len(sys.argv) > 1 else []
    asyncio.run(fetch_blocklists(urls))