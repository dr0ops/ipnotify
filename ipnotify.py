#!/usr/bin/env python3

import argparse
import fcntl
import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

APP_NAME = "ipnotify"

CONFIG_DIR = "/etc/ipnotify"
CONFIG_FILE = "/etc/ipnotify/config.json"
STATE_DIR = "/var/lib/ipnotify"
STATE_FILE = "/var/lib/ipnotify/state.json"
LOCK_FILE = "/run/ipnotify.lock"
SCRIPT_INSTALL_PATH = "/usr/local/sbin/ipnotify.py"
SYSTEMD_SERVICE = "/etc/systemd/system/ipnotify.service"
SYSTEMD_BOOT_SERVICE = "/etc/systemd/system/ipnotify-boot.service"
SYSTEMD_TIMER = "/etc/systemd/system/ipnotify.timer"
LOG_FILE = "/var/log/ipnotify.log"

DEFAULT_INTERFACES = [
    "eno2",
    "eth0",
]

DEFAULT_PUBLIC_IP_SERVICES = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
]

DEFAULT_INTERVAL = 300
DEFAULT_RETRIES = 5
DEFAULT_BACKOFF = 2

DDCLIENT_CONFIG = "/etc/ddclient/ddclient.conf"
DDCLIENT_SERVICE = "ddclient.service"
PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def hostname() -> str:
    return socket.gethostname()


def is_root() -> bool:
    return os.geteuid() == 0


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def setup_logging() -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if os.path.isdir("/var/log"):
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


LOGGER = setup_logging()


def run_command(command: Iterable[str], timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    directory = os.path.dirname(path) or "."

    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)

    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def default_config() -> Dict[str, Any]:
    return {
        "hostname": hostname(),
        "interfaces": DEFAULT_INTERFACES,
        "check_interval": DEFAULT_INTERVAL,
        "public_ip_services": DEFAULT_PUBLIC_IP_SERVICES,
        "webhook": {
            "enabled": False,
            "url": "",
            "headers": {},
            "timeout": 15,
            "method": "POST",
        },
        "pushover": {
            "enabled": True,
            "user_key": "",
            "api_token": "",
            "title": "Ubuntu server IP",
            "sound": "pushover",
        },
        "ddns": {
            "enabled": False,
            "providers": [],
            "notify_on_failure": True,
            "notify_on_recovery": True,
            "verify_dns": True,
            "verification_retries": 6,
            "verification_delay": 5,
        },
        "notifications": {
            "notify_on_boot": True,
            "notify_on_ip_change": True,
            "notify_on_ddns_failure": True,
            "notify_on_ddns_recovery": True,
        },
        "retry": {
            "retries": DEFAULT_RETRIES,
            "backoff": DEFAULT_BACKOFF,
        },
    }


def load_json_file(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_file(path: str, data: Any, mode: int = 0o600) -> None:
    atomic_write(
        path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        mode=mode,
    )


def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def load_config() -> Dict[str, Any]:
    config = default_config()

    if os.path.exists(CONFIG_FILE):
        loaded = load_json_file(CONFIG_FILE, {})
        if isinstance(loaded, dict):
            config = merge_dicts(config, loaded)

    return config


def save_config(config: Dict[str, Any]) -> None:
    save_json_file(CONFIG_FILE, config, mode=0o600)


def load_state() -> Dict[str, Any]:
    return load_json_file(
        STATE_FILE,
        {
            "boot_id": "",
            "boot_notification_sent": False,
            "observed_ip": "",
            "notified_ip": "",
            "last_interface": "",
            "interfaces": {},
            "last_check": "",
            "ddns": {},
            "public_ip_failures": 0,
            "last_public_ip_error": "",
            "ip_history": [],
        },
    )


def save_state(state: Dict[str, Any]) -> None:
    save_json_file(STATE_FILE, state, mode=0o600)


def acquire_lock() -> Optional[Any]:
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    handle = open(LOCK_FILE, "w", encoding="utf-8")

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None

    return handle


def get_boot_id() -> str:
    path = "/proc/sys/kernel/random/boot_id"

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def get_interface_ip(interface: str) -> Optional[str]:
    if not command_exists("ip"):
        return None

    try:
        result = run_command(
            [
                "ip",
                "-4",
                "-o",
                "addr",
                "show",
                "dev",
                interface,
                "scope",
                "global",
            ],
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        for part in parts:
            if "/" not in part:
                continue
            try:
                address = ipaddress.ip_interface(part)
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Interface):
                return str(address.ip)

    return None


def get_all_interface_ips(config: Dict[str, Any]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for interface in config.get("interfaces", []):
        ip = get_interface_ip(interface)
        if ip:
            result[interface] = ip
    return result


def is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def validate_public_ipv4(value: str) -> Optional[str]:
    value = value.strip()

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if not isinstance(address, ipaddress.IPv4Address):
        return None

    if is_private_ip(value):
        return None

    return value


def http_get(url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    request = urllib.request.Request(
        url,
        headers=headers or {"User-Agent": f"{APP_NAME}/1.0"},
        method="GET",
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")

    return response.status, body


def http_post_form(url: str, data: Dict[str, str], timeout: int = 15) -> Tuple[int, str]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={
            "User-Agent": f"{APP_NAME}/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")

    return response.status, body


def get_public_ip(config: Dict[str, Any]) -> Tuple[Optional[str], str]:
    services = config.get("public_ip_services", DEFAULT_PUBLIC_IP_SERVICES)
    retry_config = config.get("retry", {})
    retries = max(1, int(retry_config.get("retries", DEFAULT_RETRIES)))
    backoff = max(1, int(retry_config.get("backoff", DEFAULT_BACKOFF)))
    errors: List[str] = []

    for attempt in range(retries):
        for service in services:
            try:
                status, body = http_get(service, timeout=10)
                if status != 200:
                    errors.append(f"{service}: HTTP {status}")
                    continue

                ip = validate_public_ipv4(body)
                if ip:
                    return ip, ""

                errors.append(f"{service}: invalid IPv4 response")
            except Exception as exc:
                errors.append(f"{service}: {exc}")

        if attempt < retries - 1:
            time.sleep(backoff ** min(attempt, 4))

    return None, "; ".join(errors[-10:])


def send_webhook(config: Dict[str, Any], message: str, title: Optional[str] = None) -> Tuple[bool, str]:
    webhook = config.get("webhook", {})
    if not webhook.get("enabled", False):
        return True, "Webhook disabled"

    url = webhook.get("url", "").strip()
    if not url:
        return False, "Webhook URL is not configured"

    headers = {"User-Agent": f"{APP_NAME}/1.0"}
    for key, value in (webhook.get("headers") or {}).items():
        if isinstance(value, str):
            headers[key] = value

    payload = {
        "title": title or "Ubuntu server IP",
        "message": message,
        "host": hostname(),
        "app": APP_NAME,
    }

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={**headers, "Content-Type": "application/json"},
        method=str(webhook.get("method", "POST")).upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=int(webhook.get("timeout", 15))) as response:
            resp_body = response.read().decode("utf-8", errors="replace")
        return response.status in (200, 201, 202, 204), resp_body.strip() or "OK"
    except Exception as exc:
        return False, str(exc)


def send_pushover(config: Dict[str, Any], message: str, title: Optional[str] = None, priority: int = 0) -> Tuple[bool, str]:
    pushover = config.get("pushover", {})
    if not pushover.get("enabled", True):
        return True, "Pushover disabled"

    user_key = pushover.get("user_key", "").strip()
    api_token = pushover.get("api_token", "").strip()

    if not user_key or not api_token:
        return False, "Pushover credentials are not configured"

    data = {
        "token": api_token,
        "user": user_key,
        "message": message,
        "title": title or pushover.get("title", "Ubuntu server IP"),
        "priority": str(priority),
    }

    sound = pushover.get("sound", "")
    if sound:
        data["sound"] = sound

    retries = int(config.get("retry", {}).get("retries", DEFAULT_RETRIES))
    backoff = int(config.get("retry", {}).get("backoff", DEFAULT_BACKOFF))
    last_error = ""

    for attempt in range(max(1, retries)):
        try:
            status, body = http_post_form(PUSHOVER_API_URL, data, timeout=15)
            if status == 200:
                return True, body.strip()
            last_error = f"Pushover HTTP {status}: {body.strip()}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < retries - 1:
            time.sleep(backoff ** min(attempt, 4))

    return False, last_error


def send_notification(config: Dict[str, Any], message: str, title: Optional[str] = None, priority: int = 0) -> Tuple[bool, str]:
    ok, response = send_pushover(config, message, title=title, priority=priority)
    if ok:
        return True, response

    webhook = config.get("webhook", {})
    if webhook.get("enabled", False):
        ok_webhook, response_webhook = send_webhook(config, message, title=title)
        if ok_webhook:
            return True, response_webhook
        return False, f"Pushover failed: {response}; Webhook failed: {response_webhook}"

    return False, response


def add_ip_history(state: Dict[str, Any], public_ip: str, reason: str) -> None:
    history = state.setdefault("ip_history", [])
    item = {
        "timestamp": now_iso(),
        "ip": public_ip,
        "reason": reason,
    }

    history.append(item)
    state["ip_history"] = history[-50:]


def update_duckdns(provider: Dict[str, Any], public_ip: str) -> Tuple[bool, str]:
    hostname_value = provider.get("hostname", "").strip()
    token = provider.get("token", "").strip()

    if not hostname_value:
        return False, "DuckDNS hostname is missing"
    if not token:
        return False, "DuckDNS token is missing"

    hostname_value = hostname_value.removesuffix(".duckdns.org")
    query = urllib.parse.urlencode({
        "domains": hostname_value,
        "token": token,
        "ip": public_ip,
    })
    url = "https://www.duckdns.org/update?" + query

    try:
        status, body = http_get(url, timeout=15)
    except Exception as exc:
        return False, str(exc)

    body = body.strip()
    if status == 200 and body.lower() == "ok":
        return True, body

    return False, f"HTTP {status}: {body}"


def update_dynu(provider: Dict[str, Any], public_ip: str) -> Tuple[bool, str]:
    hostname_value = provider.get("hostname", "").strip()
    username = provider.get("username", "").strip()
    password = provider.get("password", "").strip()

    if not hostname_value:
        return False, "Dynu hostname is missing"
    if not username:
        return False, "Dynu username is missing"
    if not password:
        return False, "Dynu password is missing"

    query = urllib.parse.urlencode({
        "hostname": hostname_value,
        "myip": public_ip,
        "username": username,
        "password": password,
    })
    url = "https://api.dynu.com/nic/update?" + query

    try:
        status, body = http_get(url, timeout=15)
    except Exception as exc:
        return False, str(exc)

    body = body.strip()
    if status == 200:
        first_line = body.splitlines()[0] if body else ""
        if first_line.startswith(("good", "nochg")):
            return True, first_line

    return False, f"HTTP {status}: {body}"


def install_package(package: str) -> Tuple[bool, str]:
    if not is_root():
        return False, "Root privileges are required"

    if not command_exists("apt-get"):
        return False, "apt-get is not available"

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    try:
        update = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300, env=env)
        if update.returncode != 0:
            return False, update.stderr.strip()

        install = subprocess.run(["apt-get", "install", "-y", package], capture_output=True, text=True, timeout=300, env=env)
        if install.returncode != 0:
            return False, install.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, f"Timed out installing {package}"
    except OSError as exc:
        return False, str(exc)

    return True, ""


def ensure_iproute2() -> Tuple[bool, str]:
    if command_exists("ip"):
        return True, "iproute2 already installed"
    return install_package("iproute2")


def ensure_ddclient() -> Tuple[bool, str]:
    if command_exists("ddclient"):
        return True, "ddclient already installed"
    return install_package("ddclient")


def configure_loopia_ddclient(provider: Dict[str, Any]) -> Tuple[bool, str]:
    hostname_value = provider.get("hostname", "").strip()
    username = provider.get("username", "").strip()
    password = provider.get("password", "").strip()

    if not hostname_value:
        return False, "Loopia hostname is missing"
    if not username:
        return False, "Loopia username is missing"
    if not password:
        return False, "Loopia password is missing"

    os.makedirs(os.path.dirname(DDCLIENT_CONFIG), exist_ok=True)
    content = (
        "daemon=0\n"
        "ssl=yes\n"
        "use=web, web=ipify-ipv4\n"
        "\n"
        "protocol=dyndns2\n"
        "server=dns.loopia.se\n"
        "script=/XDynDNSServer/XDynDNS.php\n"
        f"login={username}\n"
        f"password={password}\n"
        f"{hostname_value}\n"
    )
    atomic_write(DDCLIENT_CONFIG, content, mode=0o600)
    return True, DDCLIENT_CONFIG


def disable_ddclient_service() -> Tuple[bool, str]:
    if not command_exists("systemctl"):
        return False, "systemctl is not available"

    try:
        result = run_command(["systemctl", "disable", "--now", DDCLIENT_SERVICE], timeout=30)
    except Exception as exc:
        return False, str(exc)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "not found" not in stderr.lower() and "does not exist" not in stderr.lower():
            return False, stderr

    return True, ""


def update_loopia(provider: Dict[str, Any]) -> Tuple[bool, str]:
    ok, message = ensure_ddclient()
    if not ok:
        return False, message

    ok, message = configure_loopia_ddclient(provider)
    if not ok:
        return False, message

    disable_ddclient_service()

    try:
        result = run_command(["ddclient", "--once", "--force", "--verbose"], timeout=120)
    except subprocess.TimeoutExpired:
        return False, "ddclient timed out"
    except OSError as exc:
        return False, str(exc)

    output = (result.stdout.strip() + "\n" + result.stderr.strip()).strip()
    if result.returncode == 0:
        return True, output[-2000:]

    return False, output[-2000:]


def provider_name(provider: Dict[str, Any]) -> str:
    return provider.get("name", provider.get("provider", "unknown"))


def update_provider(provider: Dict[str, Any], public_ip: str) -> Tuple[bool, str]:
    provider_type = provider.get("provider", "").lower().strip()

    if provider_type == "duckdns":
        return update_duckdns(provider, public_ip)
    if provider_type == "dynu":
        return update_dynu(provider, public_ip)
    if provider_type == "loopia":
        return update_loopia(provider)

    return False, f"Unsupported DDNS provider: {provider_type}"


def resolve_ipv4(hostname_value: str) -> List[str]:
    try:
        results = socket.getaddrinfo(hostname_value, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    addresses: List[str] = []
    for result in results:
        address = result[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def verify_dns(hostname_value: str, expected_ip: str, retries: int = 6, delay: int = 5) -> Tuple[bool, str]:
    hostname_value = hostname_value.strip()
    if not hostname_value:
        return False, "Hostname is missing"

    last_addresses: List[str] = []
    for attempt in range(max(1, retries)):
        addresses = resolve_ipv4(hostname_value)
        last_addresses = addresses
        if expected_ip in addresses:
            return True, ", ".join(addresses)

        if attempt < retries - 1:
            time.sleep(delay)

    if last_addresses:
        return False, "Resolved: " + ", ".join(last_addresses)

    return False, "No IPv4 address resolved"


def verify_provider_dns(config: Dict[str, Any], provider: Dict[str, Any], expected_ip: str) -> Tuple[bool, str]:
    provider_type = provider.get("provider", "").lower().strip()
    if provider_type in ("duckdns", "dynu", "loopia"):
        hostname_value = provider.get("hostname", "").strip()
    else:
        return False, "Unsupported provider"

    ddns_config = config.get("ddns", {})
    retries = int(ddns_config.get("verification_retries", 6))
    delay = int(ddns_config.get("verification_delay", 5))
    return verify_dns(hostname_value, expected_ip, retries, delay)


def update_ddns(config: Dict[str, Any], public_ip: str, state: Dict[str, Any]) -> List[Dict[str, Any]]:
    ddns_config = config.get("ddns", {})
    if not ddns_config.get("enabled", False):
        return []

    providers = ddns_config.get("providers", [])
    results: List[Dict[str, Any]] = []

    for provider in providers:
        name = provider_name(provider)
        started = time.time()
        ok, message = update_provider(provider, public_ip)

        result = {
            "provider": name,
            "type": provider.get("provider", ""),
            "hostname": provider.get("hostname", ""),
            "success": ok,
            "message": message,
            "timestamp": now_iso(),
            "ip": public_ip,
            "duration": round(time.time() - started, 2),
        }

        if ok and ddns_config.get("verify_dns", True):
            verify_ok, verify_message = verify_provider_dns(config, provider, public_ip)
            result["dns_verified"] = verify_ok
            result["dns_message"] = verify_message
            if not verify_ok:
                result["success"] = False
        else:
            result["dns_verified"] = None
            result["dns_message"] = ""

        provider_state = state.setdefault("ddns", {}).setdefault(name, {})
        previous_success = provider_state.get("success")
        provider_state.update({
            "success": result["success"],
            "last_attempt": result["timestamp"],
            "last_ip": public_ip,
            "message": result["message"],
            "dns_verified": result["dns_verified"],
            "dns_message": result["dns_message"],
        })
        result["previous_success"] = previous_success
        results.append(result)

    return results


def format_ddns_results(results: List[Dict[str, Any]]) -> str:
    if not results:
        return "DDNS: disabled"

    lines: List[str] = []
    for result in results:
        status = "OK" if result["success"] else "FAILED"
        line = f"{result['provider']}: {status}"
        if result.get("dns_verified") is True:
            line += " / DNS OK"
        elif result.get("dns_verified") is False:
            line += " / DNS FAILED"
        lines.append(line)

    return "\n".join(lines)


def build_ip_message(public_ip: str, interface: str, interfaces: Dict[str, str], reason: str, ddns_results: Optional[List[Dict[str, Any]]] = None) -> str:
    lines = [
        f"Host: {hostname()}",
        f"Reason: {reason}",
        f"Public IPv4: {public_ip}",
    ]

    if interface:
        lines.append(f"Interface: {interface}")

    if interfaces:
        lines.append("Local IPv4:")
        for name, ip in interfaces.items():
            lines.append(f"  {name}: {ip}")

    if ddns_results is not None:
        lines.append("")
        lines.append(format_ddns_results(ddns_results))

    return "\n".join(lines)


def select_preferred_interface(config: Dict[str, Any], interfaces: Dict[str, str]) -> str:
    configured = config.get("interfaces", [])
    for interface in configured:
        if interface in interfaces:
            return interface
    if interfaces:
        return next(iter(interfaces))
    return ""


def get_network_info(config: Dict[str, Any]) -> Tuple[Optional[str], str, Dict[str, str], str]:
    interfaces = get_all_interface_ips(config)
    interface = select_preferred_interface(config, interfaces)
    public_ip, error = get_public_ip(config)
    return public_ip, interface, interfaces, error


def notify_ddns_changes(config: Dict[str, Any], state: Dict[str, Any], ddns_results: List[Dict[str, Any]]) -> None:
    notifications = config.get("notifications", {})

    for result in ddns_results:
        provider = result["provider"]
        provider_state = state.setdefault("ddns", {}).setdefault(provider, {})
        previous_success = result.get("previous_success")
        current_success = result["success"]

        should_notify = False
        reason = ""

        if not current_success and previous_success is not False and notifications.get("notify_on_ddns_failure", True):
            should_notify = True
            reason = "DDNS update failed"
        elif current_success and previous_success is False and notifications.get("notify_on_ddns_recovery", True):
            should_notify = True
            reason = "DDNS recovered"

        if not should_notify:
            continue

        message = (
            f"Host: {hostname()}\n"
            f"Provider: {provider}\n"
            f"Reason: {reason}\n"
            f"Public IPv4: {result['ip']}\n"
            f"Message: {result['message']}"
        )
        if result.get("dns_message"):
            message += "\nDNS: " + result["dns_message"]

        ok, _ = send_notification(config, message, title="Ubuntu DDNS", priority=1 if not current_success else 0)
        provider_state["last_notification_success"] = ok


def show_status(config: Dict[str, Any], state: Dict[str, Any]) -> None:
    public_ip, interface, interfaces, error = get_network_info(config)

    print(f"Host:          {hostname()}")
    print(f"Platform:      {platform.platform()}")
    print(f"Public IPv4:   {public_ip or 'unavailable'}")
    if error:
        print(f"IP error:      {error}")

    print(f"Interface:     {interface or 'none'}")
    print("Local IPv4:")
    if interfaces:
        for name, ip in interfaces.items():
            print(f"  {name}: {ip}")
    else:
        print("  none")

    print(f"Observed IP:   {state.get('observed_ip') or 'none'}")
    print(f"Notified IP:   {state.get('notified_ip') or 'none'}")
    print(f"Boot ID:       {state.get('boot_id') or 'none'}")
    print(f"Boot notified: {state.get('boot_notification_sent', False)}")
    print(f"Last check:    {state.get('last_check') or 'never'}")
    print(f"IP failures:   {state.get('public_ip_failures', 0)}")

    print("")
    print("DDNS:")
    ddns_state = state.get("ddns", {})
    if not ddns_state:
        print("  none")
    else:
        for name, item in ddns_state.items():
            status = "OK" if item.get("success") else "FAILED"
            print(f"  {name}: {status} {item.get('last_ip', '')}")

    print("")
    print("Systemd:")
    for unit in ("ipnotify.service", "ipnotify-boot.service", "ipnotify.timer"):
        if command_exists("systemctl"):
            try:
                result = run_command(["systemctl", "is-enabled", unit], timeout=10)
                enabled = result.stdout.strip() if result.returncode == 0 else "disabled"

                result = run_command(["systemctl", "is-active", unit], timeout=10)
                active = result.stdout.strip() if result.returncode == 0 else "inactive"
                print(f"  {unit}: {enabled}, {active}")
            except Exception:
                print(f"  {unit}: unavailable")


def redact_config(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        secret_keys = {"user_key", "api_token", "token", "password"}
        for key, item in value.items():
            if key in secret_keys and item:
                result[key] = "***REDACTED***"
            else:
                result[key] = redact_config(item)
        return result

    if isinstance(value, list):
        return [redact_config(item) for item in value]

    return value


def install_script() -> Tuple[bool, str]:
    if not is_root():
        return False, "Root privileges are required"

    source = os.path.abspath(__file__)
    if source == SCRIPT_INSTALL_PATH:
        os.chmod(SCRIPT_INSTALL_PATH, 0o755)
        return True, SCRIPT_INSTALL_PATH

    try:
        os.makedirs(os.path.dirname(SCRIPT_INSTALL_PATH), exist_ok=True)
        shutil.copy2(source, SCRIPT_INSTALL_PATH)
        os.chmod(SCRIPT_INSTALL_PATH, 0o755)
    except OSError as exc:
        return False, str(exc)

    return True, SCRIPT_INSTALL_PATH


def install_systemd(config: Dict[str, Any]) -> Tuple[bool, str]:
    if not is_root():
        return False, "Root privileges are required"

    interval = max(30, int(config.get("check_interval", DEFAULT_INTERVAL)))

    service = f"""[Unit]
Description=IP notification and DDNS check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {SCRIPT_INSTALL_PATH}
"""

    boot_service = f"""[Unit]
Description=IP notification boot check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {SCRIPT_INSTALL_PATH}

[Install]
WantedBy=multi-user.target
"""

    timer = f"""[Unit]
Description=Periodic IP notification and DDNS check

[Timer]
OnBootSec=30s
OnUnitActiveSec={interval}s
AccuracySec=10s
Persistent=true
Unit=ipnotify.service

[Install]
WantedBy=timers.target
"""

    atomic_write(SYSTEMD_SERVICE, service, mode=0o644)
    atomic_write(SYSTEMD_BOOT_SERVICE, boot_service, mode=0o644)
    atomic_write(SYSTEMD_TIMER, timer, mode=0o644)

    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
        subprocess.run(["systemctl", "enable", "ipnotify-boot.service"], check=True, timeout=30)
        subprocess.run(["systemctl", "enable", "--now", "ipnotify.timer"], check=True, timeout=30)
    except Exception as exc:
        return False, str(exc)

    return True, ""


def install_dependencies(config: Dict[str, Any]) -> Tuple[bool, str]:
    ok, message = ensure_iproute2()
    if not ok:
        return False, "Could not install iproute2: " + message

    providers = config.get("ddns", {}).get("providers", [])
    if any(provider.get("provider", "").lower() == "loopia" for provider in providers):
        ok, message = ensure_ddclient()
        if not ok:
            return False, "Could not install ddclient: " + message

    return True, ""


def configure_all_ddns(config: Dict[str, Any]) -> Tuple[bool, str]:
    providers = config.get("ddns", {}).get("providers", [])
    for provider in providers:
        if provider.get("provider", "").lower() == "loopia":
            ok, message = configure_loopia_ddclient(provider)
            if not ok:
                return False, message
            disable_ddclient_service()
    return True, ""


def install_everything(config: Dict[str, Any]) -> int:
    if not is_root():
        print("ERROR: run --install as root.", file=sys.stderr)
        return 1

    ok, message = install_dependencies(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = install_script()
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = configure_all_ddns(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = install_systemd(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    print("Installation complete.")
    print(f"Script:  {SCRIPT_INSTALL_PATH}")
    print(f"Config:  {CONFIG_FILE}")
    print(f"State:   {STATE_FILE}")
    print(f"Timer:   every {config.get('check_interval', DEFAULT_INTERVAL)} seconds")
    return 0


def repair_installation(config: Dict[str, Any]) -> int:
    if not is_root():
        print("ERROR: run --repair as root.", file=sys.stderr)
        return 1

    print("Repairing installation...")

    ok, message = install_dependencies(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = install_script()
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = configure_all_ddns(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    ok, message = install_systemd(config)
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1

    print("Repair complete.")
    return 0


def uninstall() -> int:
    if not is_root():
        print("ERROR: run --uninstall as root.", file=sys.stderr)
        return 1

    if command_exists("systemctl"):
        for unit in ("ipnotify.timer", "ipnotify-boot.service"):
            try:
                subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True, text=True, timeout=30)
            except Exception:
                pass
        try:
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=30)
        except Exception:
            pass

    for path in (SYSTEMD_SERVICE, SYSTEMD_BOOT_SERVICE, SYSTEMD_TIMER, SCRIPT_INSTALL_PATH):
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError as exc:
            print(f"WARNING: could not remove {path}: {exc}")

    if command_exists("systemctl"):
        try:
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=30)
        except Exception:
            pass

    print("ipnotify systemd installation removed.")
    print(f"Configuration retained at {CONFIG_FILE}")
    print(f"State retained at {STATE_FILE}")
    print("ddclient was not removed.")
    return 0


def validate_config(config: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    if platform.system() != "Linux":
        errors.append("This script is intended for Linux")

    if not command_exists("python3"):
        errors.append("python3 command not found")

    if not command_exists("systemctl"):
        errors.append("systemctl command not found")

    if not command_exists("ip"):
        errors.append("ip command not found; install iproute2")

    interval = int(config.get("check_interval", DEFAULT_INTERVAL))
    if interval < 30:
        errors.append("check_interval must be at least 30 seconds")

    if not config.get("interfaces"):
        errors.append("No network interfaces configured")

    if not config.get("public_ip_services"):
        errors.append("No public IP detection services configured")

    pushover = config.get("pushover", {})
    if pushover.get("enabled", True):
        if not pushover.get("user_key"):
            errors.append("Pushover user key missing")
        if not pushover.get("api_token"):
            errors.append("Pushover API token missing")

    ddns = config.get("ddns", {})
    if ddns.get("enabled", False) and not ddns.get("providers"):
        errors.append("DDNS enabled but no providers configured")

    webhook = config.get("webhook", {})
    if webhook.get("enabled", False) and not webhook.get("url", "").strip():
        errors.append("Webhook enabled but URL is missing")

    return errors


def check_configuration(config: Dict[str, Any]) -> int:
    errors = validate_config(config)
    warnings: List[str] = []

    print("ipnotify configuration check")
    print("")

    if not is_root():
        warnings.append("Not running as root")

    print(f"Config file:   {'OK' if os.path.exists(CONFIG_FILE) else 'MISSING'}")
    print(f"State file:    {'OK' if os.path.exists(STATE_FILE) else 'not created yet'}")
    print(f"iproute2:      {'OK' if command_exists('ip') else 'MISSING'}")

    pushover = config.get("pushover", {})
    if pushover.get("enabled", True):
        if pushover.get("user_key"):
            print("Pushover user: OK")
        else:
            print("Pushover user: MISSING")

        if pushover.get("api_token"):
            print("Pushover token: OK")
        else:
            print("Pushover token: MISSING")
    else:
        print("Pushover:       disabled")

    print("")
    print("Interfaces:")
    for interface in config.get("interfaces", []):
        ip = get_interface_ip(interface)
        if ip:
            print(f"  {interface}: {ip}")
        else:
            warnings.append(f"Interface {interface} has no IPv4 address")
            print(f"  {interface}: unavailable")

    print("")
    print("Public IPv4:")
    public_ip, error = get_public_ip(config)
    if public_ip:
        print(f"  {public_ip}")
    else:
        errors.append("Could not determine public IPv4")
        print(f"  FAILED: {error}")

    print("")
    print("DDNS:")
    ddns = config.get("ddns", {})
    if not ddns.get("enabled", False):
        print("  disabled")
    else:
        for provider in ddns.get("providers", []):
            name = provider_name(provider)
            provider_type = provider.get("provider", "")
            print(f"  {name}: {provider_type}")
            if provider_type == "loopia":
                if command_exists("ddclient"):
                    print("    ddclient: OK")
                else:
                    errors.append("Loopia configured but ddclient is missing")
                    print("    ddclient: MISSING")
            hostname_value = provider.get("hostname", "")
            if hostname_value:
                print(f"    hostname: {hostname_value}")
            else:
                errors.append(f"{name}: hostname missing")

    print("")
    print("Systemd:")
    for path in (SYSTEMD_SERVICE, SYSTEMD_BOOT_SERVICE, SYSTEMD_TIMER):
        exists = os.path.exists(path)
        print(f"  {path}: {'OK' if exists else 'MISSING'}")
        if not exists:
            warnings.append(f"Missing systemd unit: {path}")

    if command_exists("systemctl"):
        try:
            result = run_command(["systemctl", "is-enabled", "ipnotify.timer"], timeout=10)
            print("  ipnotify.timer enabled: " + ("YES" if result.returncode == 0 else "NO"))
        except Exception:
            pass

    if errors:
        print("")
        print("Errors:")
        for error in errors:
            print(f"  ERROR: {error}")

    if warnings:
        print("")
        print("Warnings:")
        for warning in warnings:
            print(f"  WARNING: {warning}")

    print("")
    if errors:
        print("CHECK FAILED")
        return 1

    print("CHECK PASSED")
    return 0


def show_logs() -> int:
    if not command_exists("journalctl"):
        print("journalctl is not available.", file=sys.stderr)
        return 1

    try:
        result = run_command(["journalctl", "-u", "ipnotify.service", "-u", "ipnotify-boot.service", "-n", "100", "--no-pager"], timeout=30)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def interactive_setup() -> int:
    if not is_root():
        print("ERROR: --setup must be run as root.", file=sys.stderr)
        return 1

    config = default_config()

    print("ipnotify setup")
    print("")
    print(f"Network interfaces [{', '.join(config['interfaces'])}]:")
    value = input("> ").strip()
    if value:
        config["interfaces"] = [item.strip() for item in value.split(",") if item.strip()]

    print("")
    print(f"Check interval in seconds [{DEFAULT_INTERVAL}]:")
    value = input("> ").strip()
    if value:
        try:
            config["check_interval"] = max(30, int(value))
        except ValueError:
            print("Invalid interval; using default.")

    print("")
    print("Enable Pushover notifications? [Y/n]")
    value = input("> ").strip().lower()
    config["pushover"]["enabled"] = value not in ("n", "no")
    if config["pushover"]["enabled"]:
        print("")
        print("Pushover user key:")
        config["pushover"]["user_key"] = input("> ").strip()
        print("")
        print("Pushover API token:")
        config["pushover"]["api_token"] = input("> ").strip()

    print("")
    print("Send notification on every boot? [Y/n]")
    value = input("> ").strip().lower()
    config["notifications"]["notify_on_boot"] = value not in ("n", "no")

    print("")
    print("Send notification when public IP changes? [Y/n]")
    value = input("> ").strip().lower()
    config["notifications"]["notify_on_ip_change"] = value not in ("n", "no")

    print("")
    print("Enable DDNS? [y/N]")
    value = input("> ").strip().lower()
    config["ddns"]["enabled"] = value in ("y", "yes")

    providers = []
    if config["ddns"]["enabled"]:
        print("")
        print("Configure Loopia? [y/N]")
        value = input("> ").strip().lower()
        if value in ("y", "yes"):
            print("")
            print("Loopia hostname:")
            hostname_value = input("> ").strip()
            print("Loopia username:")
            username = input("> ").strip()
            print("Loopia password:")
            password = input("> ").strip()
            providers.append({
                "name": "Loopia",
                "provider": "loopia",
                "hostname": hostname_value,
                "username": username,
                "password": password,
            })

        print("")
        print("Configure DuckDNS? [y/N]")
        value = input("> ").strip().lower()
        if value in ("y", "yes"):
            print("")
            print("DuckDNS hostname:")
            hostname_value = input("> ").strip()
            print("DuckDNS token:")
            token = input("> ").strip()
            providers.append({
                "name": "DuckDNS",
                "provider": "duckdns",
                "hostname": hostname_value,
                "token": token,
            })

        print("")
        print("Configure Dynu? [y/N]")
        value = input("> ").strip().lower()
        if value in ("y", "yes"):
            print("")
            print("Dynu hostname:")
            hostname_value = input("> ").strip()
            print("Dynu username:")
            username = input("> ").strip()
            print("Dynu password:")
            password = input("> ").strip()
            providers.append({
                "name": "Dynu",
                "provider": "dynu",
                "hostname": hostname_value,
                "username": username,
                "password": password,
            })

    config["ddns"]["providers"] = providers

    print("")
    print("Verify DDNS hostname after update? [Y/n]")
    value = input("> ").strip().lower()
    config["ddns"]["verify_dns"] = value not in ("n", "no")

    save_config(config)
    os.makedirs(STATE_DIR, exist_ok=True)

    print("")
    print(f"Configuration saved to {CONFIG_FILE}")
    print("")
    print("Installing components...")
    return install_everything(config)


def run_once(config: Dict[str, Any], force: bool = False, dry_run: bool = False, test: bool = False) -> int:
    state = load_state()
    current_boot_id = get_boot_id()
    new_boot = bool(current_boot_id) and current_boot_id != state.get("boot_id", "")

    if new_boot:
        state["boot_id"] = current_boot_id
        state["boot_notification_sent"] = False

    public_ip, interface, interfaces, error = get_network_info(config)

    if not public_ip:
        state["public_ip_failures"] = state.get("public_ip_failures", 0) + 1
        state["last_public_ip_error"] = error
        state["last_check"] = now_iso()
        if not dry_run:
            save_state(state)
        print("ERROR: unable to determine public IPv4.", file=sys.stderr)
        print(error, file=sys.stderr)
        return 1

    state["public_ip_failures"] = 0
    state["last_public_ip_error"] = ""

    previous_observed_ip = state.get("observed_ip", "")
    ip_changed = bool(previous_observed_ip) and previous_observed_ip != public_ip
    first_observation = not previous_observed_ip

    boot_notification_needed = (
        config.get("notifications", {}).get("notify_on_boot", True)
        and not state.get("boot_notification_sent", False)
        and new_boot
    )
    if not current_boot_id:
        boot_notification_needed = (
            config.get("notifications", {}).get("notify_on_boot", True)
            and not state.get("boot_notification_sent", False)
        )

    ddns_results: List[Dict[str, Any]] = []
    if not dry_run and config.get("ddns", {}).get("enabled", False):
        ddns_results = update_ddns(config, public_ip, state)
        notify_ddns_changes(config, state, ddns_results)

    should_notify_ip = False
    reason = ""
    notifications = config.get("notifications", {})

    if force:
        should_notify_ip = True
        reason = "Forced check"
    elif ip_changed and notifications.get("notify_on_ip_change", True):
        should_notify_ip = True
        reason = "Public IP changed"
    elif boot_notification_needed:
        should_notify_ip = True
        reason = "Server boot"
    elif first_observation and notifications.get("notify_on_boot", True):
        should_notify_ip = True
        reason = "Initial IP detected"

    message = build_ip_message(public_ip, interface, interfaces, reason or "IP check", ddns_results)
    notification_success = True

    if should_notify_ip:
        if dry_run:
            print("")
            print("DRY RUN - would send notification:")
            print(message)
        else:
            notification_success, response = send_notification(
                config,
                message,
                title=config.get("pushover", {}).get("title", "Ubuntu server IP"),
            )
            if notification_success:
                state["notified_ip"] = public_ip
                if boot_notification_needed or reason == "Server boot":
                    state["boot_notification_sent"] = True
                print("Pushover notification sent.")
            else:
                print("ERROR: Pushover notification failed:", response, file=sys.stderr)

    if dry_run:
        print("")
        print(f"Public IPv4: {public_ip}")
        if interface:
            print(f"Interface:   {interface}")
        if interfaces:
            print("Local IPv4:")
            for name, ip in interfaces.items():
                print(f"  {name}: {ip}")
        if ddns_results:
            print("")
            print(format_ddns_results(ddns_results))
        return 0

    state["observed_ip"] = public_ip
    state["last_interface"] = interface
    state["interfaces"] = interfaces
    state["last_check"] = now_iso()
    add_ip_history(state, public_ip, reason or "IP check")
    save_state(state)

    print(f"Public IPv4: {public_ip}")
    if interface:
        print(f"Interface:   {interface}")
    if ip_changed:
        print(f"IP changed:  {previous_observed_ip} -> {public_ip}")
    if ddns_results:
        print("")
        print(format_ddns_results(ddns_results))
    if should_notify_ip:
        print("Notification: sent" if notification_success else "Notification: pending retry")
    if test:
        print("Test notification requested.")

    return 0


def run_test(config: Dict[str, Any]) -> int:
    public_ip, interface, interfaces, error = get_network_info(config)
    if not public_ip:
        print("ERROR: no public IPv4 available:", error, file=sys.stderr)
        return 1

    message = build_ip_message(public_ip, interface, interfaces, "Manual test")
    ok, response = send_notification(config, message, title="Ubuntu IP test")
    if ok:
        print("Notification test sent successfully.")
        return 0

    print(f"Notification test failed: {response}", file=sys.stderr)
    return 1


def show_history(state: Dict[str, Any]) -> None:
    history = state.get("ip_history", [])
    if not history:
        print("No IP change history available.")
        return

    print("IP change history:")
    for item in history:
        print(f"- {item.get('timestamp', 'unknown')}: {item.get('ip', 'unknown')} ({item.get('reason', 'unknown')})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor public IPv4, notify via Pushover and update DDNS.")
    parser.add_argument("--setup", action="store_true", help="Interactive setup and installation")
    parser.add_argument("--install", action="store_true", help="Install script, dependencies and systemd")
    parser.add_argument("--repair", action="store_true", help="Repair dependencies/systemd installation")
    parser.add_argument("--uninstall", action="store_true", help="Remove ipnotify systemd installation")
    parser.add_argument("--check", action="store_true", help="Check configuration")
    parser.add_argument("--status", action="store_true", help="Show current status")
    parser.add_argument("--logs", action="store_true", help="Show recent systemd logs")
    parser.add_argument("--show-config", action="store_true", help="Show configuration with secrets redacted")
    parser.add_argument("--dry-run", action="store_true", help="Check IP/DDNS without saving state or sending notifications")
    parser.add_argument("--test", action="store_true", help="Send a notification test")
    parser.add_argument("--force", action="store_true", help="Force notification and DDNS update")
    parser.add_argument("--history", action="store_true", help="Show recent IP change history")
    parser.add_argument("--validate-config", action="store_true", help="Validate config and print any errors")

    args = parser.parse_args()

    if args.setup:
        return interactive_setup()

    if args.uninstall:
        return uninstall()

    config = load_config()

    if args.show_config:
        print(json.dumps(redact_config(config), indent=2, sort_keys=True))
        return 0

    if args.install:
        return install_everything(config)

    if args.repair:
        return repair_installation(config)

    if args.check:
        return check_configuration(config)

    if args.status:
        show_status(config, load_state())
        return 0

    if args.logs:
        return show_logs()

    if args.history:
        show_history(load_state())
        return 0

    if args.validate_config:
        errors = validate_config(config)
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
        print("Configuration is valid.")
        return 0

    if args.test:
        lock = acquire_lock()
        if lock is None:
            print("Another ipnotify process is running.", file=sys.stderr)
            return 1
        try:
            return run_test(config)
        finally:
            lock.close()

    lock = acquire_lock()
    if lock is None:
        print("Another ipnotify process is running.", file=sys.stderr)
        return 1

    try:
        return run_once(config, force=args.force, dry_run=args.dry_run)
    finally:
        lock.close()


if __name__ == "__main__":
    sys.exit(main())
