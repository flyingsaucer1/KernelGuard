# Arshpreet's Phase 2 files

These files come from the local `C:\KernalGuard-Phase2-PBL` presentation copy. Its
`docs/TEAM.md` maps Arshpreet Singh's demonstration area to the Linux Audit
rules, audit parser, writer coordination, and the collector section of `app.py`.
The presentation copy says that several files were integrated or rewritten
later; this folder does not establish individual authorship or preserve the
team's original Git history.

| File here | Original path | Purpose |
| --- | --- | --- |
| `linux/kernelguard.rules` | `linux/kernelguard.rules` | Linux Audit file and process observation rules |
| `kernelguard/parser.py` | `kernelguard/parser.py` | Audit record parsing and metadata extraction |
| `kernelguard/locking.py` | `kernelguard/locking.py` | MySQL writer lock coordination |
| `app_collector_excerpt.py.txt` | Collector section of `app.py` | Audit collection, checkpoint recovery, and cursor commit |

The three whole files are unchanged copies. The collector excerpt is copied
from between the Arshpreet markers in `app.py`. These files depend on other
parts of the Phase 2 application, including `kernelguard.core`, its database
schema, and configuration. Use the complete Phase 2 project to run them.
They are stored separately from this repository's root application so the
existing app continues to use its own files.
