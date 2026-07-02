# PentNote MyScanner Plugin Example

This is a minimal installable parser plugin for PentNote. It parses a fictional `MyScanner` output format and demonstrates hosts, credentials, and findings.

Install it in editable mode:

```bash
cd examples/plugin_example
pip install -e .
pentnote parsers list | grep myscanner
```

Sample input:

```text
[MyScanner] Scan complete
HOST 10.10.10.10 web01 Linux
CRED alice:Password123!@10.10.10.10
VULN 10.10.10.10 Public exploit found
```
