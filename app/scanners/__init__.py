"""Scanner integration layer for Semgrep, OWASP ZAP, and Dependency-Check.

The adapters accept native-style scanner JSON and return the project's canonical
VulnerabilityFinding objects. Runner modules can call real tools when installed,
or use bundled fixtures for offline demos.
"""
