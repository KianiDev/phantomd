# tests/test_list_updater.py
import os
import tempfile
from utils.ListUpdater import fetch_blocklists_sync


def test_fetch_local_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("0.0.0.0 bad.example.com\n")
        source_path = f.name

    dest_dir = tempfile.mkdtemp()
    try:
        results = fetch_blocklists_sync([source_path], destination_dir=dest_dir)
        assert len(results) == 1
        src, ok = results[0]
        assert src == source_path
        assert ok is True
        dest_file = os.path.join(dest_dir, os.path.basename(source_path))
        assert os.path.exists(dest_file)
        with open(dest_file) as f:
            content = f.read()
        assert "0.0.0.0 bad.example.com" in content  # Check the full blocklist line
    finally:
        os.unlink(source_path)
        for f in os.listdir(dest_dir):
            os.unlink(os.path.join(dest_dir, f))
        os.rmdir(dest_dir)

def test_fetch_nonexistent_local():
    dest_dir = tempfile.mkdtemp()
    try:
        results = fetch_blocklists_sync(['/no/such/file.txt'], destination_dir=dest_dir)
        assert len(results) == 1
        _, ok = results[0]
        assert ok is False
    finally:
        os.rmdir(dest_dir)