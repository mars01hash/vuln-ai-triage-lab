# MCP Tool Contracts Module

This component exposes standard tool definitions and schemas that align with the Model Context Protocol (MCP) specification, allowing LLM agents to invoke normalization and enrichment logic.

## Files
* `tool_contracts.py`: Exposes tool schemas and mapping handlers.

## Usage
Exposes tools such as:
1. `normalize_vulnerability_to_cwe`: Calls the internal CWE classifier.
2. `enrich_with_threat_intel`: Connects findings to threat intelligence feeds.

## Why it works
Modern AppSec engineering uses LLM agents to perform complex reasoning. Exposing security tools via MCP schemas allows agents to interact with localized static analysis, database, and threat feed tools in a structured, safe, and repeatable format.
