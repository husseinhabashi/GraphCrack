#!/usr/bin/env python3
"""
setup.py — improved for GraphQL Crack Engine
Keep this minimal; prefer pyproject.toml for builds (PEP 517).
"""

from setuptools import setup, find_packages
from pathlib import Path
import io
import sys

ROOT = Path(__file__).parent

def read_requirements(req_path: str = "requirements.txt"):
    p = ROOT / req_path
    if not p.exists():
        return []
    lines = []
    # safe read, ignore comments and editable/git refs by default
    with io.open(p, "r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            # skip editable installs (you may want to include them separately)
            if ln.startswith("-e ") or ln.startswith("git+"):
                continue
            lines.append(ln)
    return lines

def read_long_description(readme: str = "README.md"):
    p = ROOT / readme
    if not p.exists():
        return "GraphQL Crack Engine - Advanced Graphql Security Assessment Toolkit"
    return p.read_text(encoding="utf-8")

# metadata
NAME = "graphql-crack-engine"
VERSION = "1.0.0"
DESCRIPTION = "Advanced GraphQL Security Assessment Toolkit"
AUTHOR = "Security Researcher"
AUTHOR_EMAIL = "research@example.com"
URL = "https://github.com/yourusername/graphql-crack-engine"
LICENSE = "MIT"

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    url=URL,
    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    include_package_data=True,
    install_requires=read_requirements(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            # ensure graphql_crack.py is inside a package or a module importable at install time
            "graphql-crack=graphql_crack:main",
            "gql-crack=graphql_crack:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    keywords="graphql security pentest jwt brute-force",
    license=LICENSE,
    zip_safe=False,
)