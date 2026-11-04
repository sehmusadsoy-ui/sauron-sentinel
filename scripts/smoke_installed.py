"""Verify installed package resources and local HTTP delivery without live collection."""

import json
import tempfile
import threading
from importlib import resources
from pathlib import Path
from urllib.request import urlopen

from sauron_sentinel import __version__
from sauron_sentinel.live import DashboardServer, EventStore, LiveMonitor


def main() -> None:
    package = resources.files("sauron_sentinel")
    assert package.joinpath("windows_collector.ps1").is_file()
    for name in ("index.html", "app.js", "styles.css"):
        assert package.joinpath("static", name).is_file()

    with tempfile.TemporaryDirectory(prefix="sentinel-installed-") as directory:
        store = EventStore(Path(directory))
        monitor = LiveMonitor(store)
        server = DashboardServer(monitor, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for endpoint in ("/", "/app.js", "/styles.css"):
                with urlopen(server.url + endpoint, timeout=5) as response:
                    assert response.status == 200 and response.read()
            with urlopen(server.url + "/api/state", timeout=5) as response:
                state = json.load(response)
                assert state["version"] == __version__
                assert state["summary"]["events_total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            monitor.stop()
            store.close()
    print("Installed resources and loopback dashboard verified.")


if __name__ == "__main__":
    main()
