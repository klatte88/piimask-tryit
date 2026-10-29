"""
`piimask-tryit`: start the local try-it app, save a feedback bundle, show where
the log is, or forget everything.

    piimask-tryit [start] [--no-browser]
    piimask-tryit bundle
    piimask-tryit where
    piimask-tryit forget

`start` (the default) prints exactly two lines and never the URL, which holds
the secret: "The masker is running. Close this window to stop it." and "De
verberger draait. Sluit dit venster om te stoppen." It opens the page with
`webbrowser.open` (not with `--no-browser`). A second `start` that finds a live
copy opens that copy's page and exits 0 with two lines, English then Dutch. Ctrl+C (SIGINT), Windows
SIGBREAK, and where they exist SIGTERM and SIGHUP (a closed terminal window)
stop it; so do 8 hours without a request.

`bundle` asks the running copy for its default bundle (the reviewed prompts),
or, when none runs, builds it from the logs directly, and saves it into the
Downloads folder (`PIIMASK_TRYIT_DOWNLOADS` overrides); it prints only the
saved path. `where` prints the log folder only. `forget` asks for a typed
"yes" or "ja" and refuses while a copy runs.

Every refusal is a code or a plain sentence, never a value: a traceback could
quote one, so the boundary names only the error class.
"""

from __future__ import annotations

import argparse
import http.client
import json
import signal
import sys
import webbrowser
from collections.abc import Callable
from typing import Any

from piimask.localapp import instance, paths

APP_NAME = "piimask-tryit"

START_LINES = (
    "The masker is running. Close this window to stop it.",
    "De verberger draait. Sluit dit venster om te stoppen.",
)
ALREADY_RUNNING_LINES = (
    "The masker is already running; its page is open again.",
    "De verberger draait al; de pagina is weer geopend.",
)
EXIT_CANNOT = 2

# Injectable for tests: never open a real browser there.
open_browser: Callable[[str], Any] = webbrowser.open


def _request(info: instance.RunningInfo, method: str, route: str, token: str | None,
             body: dict[str, Any] | None = None) -> dict[str, Any]:
    """One request to the running copy, straight to 127.0.0.1 (no proxy is ever consulted)."""
    conn = http.client.HTTPConnection("127.0.0.1", info.port, timeout=30)
    try:
        hdrs = {"Host": f"127.0.0.1:{info.port}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if token is not None:
            hdrs["X-Piimask-Token"] = token
        conn.request(method, f"/{info.secret}/{route}", body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        if resp.status != 200:
            raise RuntimeError("running_copy_refused")
        out = json.loads(raw.decode("utf-8"))
        if not isinstance(out, dict):
            raise TypeError("running_copy_bad_answer")
        return out
    finally:
        conn.close()


def cmd_start(args: argparse.Namespace) -> int:
    from piimask.localapp.server import LocalApp

    home = paths.home()
    running = instance.find_running(home)
    if running is not None:
        if not args.no_browser:
            open_browser(instance.url_for(running))
        for line in ALREADY_RUNNING_LINES:
            print(line)
        return 0

    app = LocalApp(home)
    stop_signals: list[signal.Signals] = []

    def ignore_further_stops() -> None:
        # One Ctrl+C often arrives twice (the terminal signals the whole process
        # group and a launcher such as uv forwards its own copy). Once stopping
        # has begun, every later stop signal is ignored at the OS level, so it
        # can neither cut teardown short nor kill the process during interpreter
        # shutdown, when Python puts its own handlers back to the default.
        for sig in stop_signals:
            try:
                signal.signal(sig, signal.SIG_IGN)
            except (ValueError, OSError):
                continue

    def stop(_signum: int, _frame: Any) -> None:
        ignore_further_stops()
        app.shutdown_from_thread()

    names = ["SIGINT", "SIGBREAK", "SIGTERM", "SIGHUP"]
    for name in names:
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, stop)
            except (ValueError, OSError):
                continue
            stop_signals.append(sig)

    try:
        for line in START_LINES:
            print(line)
        sys.stdout.flush()
        if not args.no_browser:
            open_browser(app.url)
        app.serve_forever()
    finally:
        ignore_further_stops()  # also when the idle limit, not a signal, ended serving
        app.close()
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    from piimask.localapp.server import downloads_dir, save_bundle

    home = paths.home()
    folder = downloads_dir()
    running = instance.find_running(home)
    if running is not None:
        mode = _request(running, "GET", "mode.json", None)
        token = mode.get("token")
        if not isinstance(token, str):
            raise RuntimeError("running_copy_bad_answer")
        preview = _request(running, "POST", "bundle", token, {"action": "preview"})
        include = [p["id"] for p in preview.get("prompts", []) if isinstance(p, dict) and p.get("include")]
        saved = _request(running, "POST", "bundle", token, {"action": "save", "include": include})
        name = saved.get("file_name")
        if saved.get("ok") is not True or not isinstance(name, str):
            print("The running masker could not save the bundle. / De verberger kon het pakket niet bewaren.",
                  file=sys.stderr)
            return EXIT_CANNOT
        print(folder / name)
        return 0

    from datetime import datetime

    from piimask.localapp.log import SafeLog
    from piimask.localapp.server import app_version

    now = datetime.now().astimezone()
    log = SafeLog(home, app_version=app_version())
    path = save_bundle(log.bundle(None), folder, now)
    print(path)
    return 0


def cmd_where(args: argparse.Namespace) -> int:
    print(paths.logs_dir(paths.home()))
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    home = paths.home()
    if instance.find_running(home) is not None:
        print("Stop the masker first, then try again. / Stop eerst de verberger en probeer het opnieuw.",
              file=sys.stderr)
        return 1
    print("This deletes your masker log and state on this computer.")
    print("Dit wist het logboek en de gegevens van de verberger op deze computer.")
    answer = input('Type "yes" to delete / Typ "ja" om te wissen: ')
    if answer.strip().lower() not in ("yes", "ja"):
        print("Nothing deleted. / Er is niets gewist.")
        return 1
    try:
        deleted = instance.forget(home)
    except instance.AppRunningError:
        print("Stop the masker first, then try again. / Stop eerst de verberger en probeer het opnieuw.",
              file=sys.stderr)
        return 1
    except instance.UnsafeHomeError:
        print("That folder holds files the masker did not make, so nothing was deleted. "
              "/ Die map bevat bestanden die de verberger niet heeft gemaakt; er is niets gewist.",
              file=sys.stderr)
        return EXIT_CANNOT
    print("Deleted. / Gewist." if deleted else "There was nothing to delete. / Er was niets om te wissen.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="The PII masker on your own computer. / De verberger op je eigen computer.",
    )
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="start the masker and open its page (default)")
    p_start.add_argument("--no-browser", action="store_true", help="do not open the page")
    p_start.set_defaults(func=cmd_start)

    p_bundle = sub.add_parser("bundle", help="save a feedback bundle into your Downloads folder")
    p_bundle.set_defaults(func=cmd_bundle)

    p_where = sub.add_parser("where", help="show the log folder")
    p_where.set_defaults(func=cmd_where)

    p_forget = sub.add_parser("forget", help="delete the log and state on this computer")
    p_forget.set_defaults(func=cmd_forget)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw or (raw[0].startswith("-") and raw[0] not in ("-h", "--help")):
        raw = ["start", *raw]  # `start` is the default command
    args = parser.parse_args(raw)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 - CLI boundary: the class only, never a traceback that could quote a value
        print(f"The masker stopped with an error: {e.__class__.__name__} "
              f"/ De verberger stopte met een fout: {e.__class__.__name__}", file=sys.stderr)
        return EXIT_CANNOT


if __name__ == "__main__":
    raise SystemExit(main())
