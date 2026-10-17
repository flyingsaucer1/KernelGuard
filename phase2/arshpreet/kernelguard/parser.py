
import posixpath
import re
from collections import defaultdict
from .core import digest

IDENTITY = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
FIELD = re.compile(r'(\w+)=(?:"([^"\n]*)"|([^\s\'\"]+))')


def fields(line):
    result = {}
    for m in FIELD.finditer(line):
        value = m.group(2) if m.group(2) is not None else m.group(3)
        if m.group(2) is None and m.group(1) in ("name", "cwd", "exe", "acct"):
            value = decode_hex(value)
        result[m.group(1)] = value
    return result


def decode_hex(value):
    # Audit encodes paths/executables with special characters as hexadecimal.
    if value and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
        try:
            decoded = bytes.fromhex(value).decode("utf-8")
            return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return value


def known_id(value):
    return None if value in (None, "4294967295", "-1", "unset", "(null)") else value


def os_details(row, stamp, serial, path=None):
    path = path or {}
    return dict(audit_timestamp=stamp, audit_serial=serial, record_type=row["type"],
        login_uid=known_id(row.get("auid")), real_uid=known_id(row.get("uid")),
        effective_uid=known_id(row.get("euid")), session_id=known_id(row.get("ses")),
        syscall=row.get("syscall"), architecture=row.get("arch"),
        inode=path.get("inode"), device=path.get("dev"))


def parse_audit(text, host, origin="live", boot_id=None):
    for record in _parse_audit(text, host, origin):
        if boot_id:
            record["source_id"] = digest(f"{boot_id}:{record['source_id']}")
            record["_boot"] = boot_id
        yield record


def event_record(host, origin, stamp, serial, discriminator, kind, row,
                 account, uid, resource, outcome, path=None):
    """Build the shared audit envelope while retaining event-specific identity."""
    return dict(source_id=digest(f"{host}:{origin}:{stamp}:{serial}:{discriminator}"),
        host=host, timestamp=int(float(stamp)), kind=kind, account=account[:128],
        uid=uid, effective_uid=known_id(row.get("euid")),
        session=known_id(row.get("ses")) if kind != "login_failure" else None,
        pid=row.get("pid"), executable=row.get("exe"), resource=resource,
        outcome=outcome, origin=origin,
        _audit=os_details(row, stamp, serial, path))


def auth_records(rows, host, origin, stamp, serial):
    for index, row in enumerate(rows):
        if row.get("type") != "USER_AUTH" or row.get("res") != "failed":
            continue
        # USER_LOGIN repeats a PAM attempt; accepting it would inflate the count.
        if posixpath.basename(row.get("exe", "")) not in (
                "sshd", "sshd-session", "sshd-auth", "login"):
            continue
        yield event_record(host, origin, stamp, serial, f"auth:{index}",
            "login_failure", row, row.get("acct") or "unknown", None,
            row.get("addr"), "failure")


def path_records(rows, cwd):
    """Yield each audited target once, excluding parent-directory records."""
    seen = set()
    for row in rows:
        if row.get("type") != "PATH" or row.get("nametype") == "PARENT":
            continue
        name = row.get("name")
        if not name or name == "(null)":
            continue
        absolute = posixpath.normpath(posixpath.join(cwd or "/", name))
        if absolute not in seen:
            seen.add(absolute)
            yield absolute, row


def syscall_records(rows, host, origin, stamp, serial):
    syscall = next((row for row in rows if row.get("type") == "SYSCALL"), None)
    if syscall is None:
        return
    keys = set((syscall.get("key") or "").split(","))
    observed_uid = syscall.get("auid")
    uid = observed_uid if observed_uid not in (None, "4294967295", "-1", "unset") else syscall.get("uid")
    account = f"uid:{uid}" if uid else "unknown"
    outcome = "success" if syscall.get("success") == "yes" else "failure"
    if "kernelguard_process_exec" in keys:
        executable = syscall.get("exe")
        yield event_record(host, origin, stamp, serial, "exec", "process_exec",
            syscall, account, uid, executable, outcome)
    if keys.isdisjoint(("kernelguard_protected", "kernelguard_file_access")):
        return
    cwd = next((row.get("cwd") for row in rows if row.get("type") == "CWD"), "/")
    for name, path in path_records(rows, cwd):
        yield event_record(host, origin, stamp, serial, f"file:{name}",
            "file_access", syscall, account, uid, name, outcome, path)


def _parse_audit(text, host, origin):
    groups = defaultdict(list)
    for line in text.splitlines():
        match = IDENTITY.search(line)
        if match:
            groups[match.groups()].append(fields(line))
    for (stamp, serial), rows in sorted(groups.items(), key=lambda pair: (float(pair[0][0]), int(pair[0][1]))):
        yield from auth_records(rows, host, origin, stamp, serial)
        yield from syscall_records(rows, host, origin, stamp, serial)
