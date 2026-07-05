import os
import shutil
from pathlib import Path

def build_docs():
    root = Path(__file__).resolve().parent.parent
    docs_dir = root / "docs"
    modules_dir = docs_dir / "modules"
    screenshots_dest = docs_dir / "screenshots"

    print(">>> Initializing docs/ directory structure...")
    if docs_dir.exists():
        shutil.rmtree(docs_dir)
    docs_dir.mkdir(parents=True, exist_ok=True)
    modules_dir.mkdir(parents=True, exist_ok=True)

    mappings = {
        root / "README.md": docs_dir / "index.md",
        root / "doc" / "v5.0_explanation.md": docs_dir / "doc_v5_explanation.md",
        root / "app" / "threat_intel" / "README.md": modules_dir / "threat_intel.md",
        root / "app" / "reachability" / "README.md": modules_dir / "reachability.md",
        root / "app" / "mcp" / "README.md": modules_dir / "mcp.md",
        root / "app" / "audit" / "README.md": modules_dir / "audit.md",
    }

    # Copy files
    for src, dest in mappings.items():
        if src.exists():
            print(f"Copying {src.relative_to(root)} -> {dest.relative_to(root)}")
            shutil.copy2(src, dest)
        else:
            print(f"Warning: Source not found {src.relative_to(root)}")

    # Copy screenshots folder to docs/screenshots so relative image paths work in MkDocs
    screenshots_src = root / "screenshots"
    if screenshots_src.exists():
        print(f"Copying assets from screenshots/ to docs/screenshots/")
        shutil.copytree(screenshots_src, screenshots_dest)

    print(">>> Sync completed successfully!")
    
    # Try building if mkdocs is installed
    try:
        import subprocess
        print(">>> Running mkdocs build...")
        subprocess.run(["mkdocs", "build"], cwd=str(root), check=True)
        print(">>> MkDocs build completed. Output files generated in site/")
    except FileNotFoundError:
        print(">>> Info: mkdocs command not found. Install it with 'pip install mkdocs mkdocs-material' to build.")
    except Exception as e:
        print(f">>> Error building documentation: {e}")

if __name__ == "__main__":
    build_docs()
