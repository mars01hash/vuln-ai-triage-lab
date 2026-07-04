# Demo Vulnerable App

This small Flask app is intentionally vulnerable for portfolio testing.

Included demo weaknesses:

- SQL Injection: `/user?id=1`
- Reflected XSS: `/search?q=<script>alert(1)</script>`
- Path Traversal: `/download?file=../../etc/passwd`
- Hard-coded secret in `app.py`
- Vulnerable dependency examples in `requirements.txt`

Do not deploy this app publicly. It is only for local scanner demos.
