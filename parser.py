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

def _parse_audit(text, host, origin):
    groups = defaultdict(list)
    for line in text.splitlines():
        match = IDENTITY.search(line)
        if match:
            groups[match.groups()].append(fields(line))
    for (stamp, serial), rows in sorted(groups.items(), key=lambda pair: (float(pair[0][0]), int(pair[0][1]))):
        for index, row in enumerate(rows):
            if (row.get("type") == "USER_AUTH" and row.get("res") == "failed"
                    and posixpath.basename(row.get("exe", "")) in
                    ("sshd", "sshd-session", "sshd-auth", "login")):
                        
                account = row.get("acct") or "unknown"
                yield dict(source_id=digest(f"{host}:{origin}:{stamp}:{serial}:auth:{index}"),
                    host=host, timestamp=int(float(stamp)), kind="login_failure",
                    account=account[:128], uid=None, effective_uid=known_id(row.get("euid")),
                    session=None, pid=row.get("pid"), executable=row.get("exe"),
                    resource=row.get("addr"), outcome="failure", origin=origin,
                    _audit=os_details(row, stamp, serial))
        syscall = next((r for r in rows if r.get("type") == "SYSCALL"), None)
        if not syscall or syscall.get("key") != "kernelguard_protected":
            continue
        cwd = next((r.get("cwd") for r in rows if r.get("type") == "CWD"), "/")
        seen = set()
        for row in rows:
            if row.get("type") != "PATH" or row.get("nametype") == "PARENT":
                continue
            name = row.get("name")
            if not name or name == "(null)":
                continue
            name = posixpath.normpath(posixpath.join(cwd or "/", name))
            if name in seen:
                continue
            seen.add(name)
            auid = syscall.get("auid")
            uid = auid if auid not in (None, "4294967295", "-1", "unset") else syscall.get("uid")
            yield dict(source_id=digest(f"{host}:{origin}:{stamp}:{serial}:file:{name}"),
                host=host, timestamp=int(float(stamp)), kind="file_access",
                account=f"uid:{uid}" if uid else "unknown", uid=uid,
                effective_uid=known_id(syscall.get("euid")), session=known_id(syscall.get("ses")),
                pid=syscall.get("pid"), executable=syscall.get("exe"),
                resource=name, outcome="success" if syscall.get("success") == "yes" else "failure",
                origin=origin, _audit=os_details(syscall, stamp, serial, row))
