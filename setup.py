#!/usr/bin/env python3
"""
Setup script for GraphQL Crack Engine
"""

from setuptools import setup, find_packages
import os

def read_requirements():
    """Read requirements from requirements.txt"""
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def read_long_description():
    """Read long description from README.md"""
    try:
        with open('README.md', 'r') as f:
            return f.read()
    except:
        return "GraphQL Crack Engine - Advanced GraphQL Security Assessment Toolkit"

setup(
    name="graphql-crack-engine",
    version="1.0.0",
    description="Advanced GraphQL Security Assessment Toolkit",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="Security Researcher",
    author_email="research@example.com",
    url="https://github.com/yourusername/graphql-crack-engine",
    packages=find_packages(),
    include_package_data=True,
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'graphql-crack=graphql_crack:main',
            'gql-crack=graphql_crack:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Security Professionals",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.7",
    keywords="graphql security penetration-testing jwt brute-force",
    project_urls={
        "Documentation": "https://github.com/yourusername/graphql-crack-engine/docs",
        "Source": "https://github.com/yourusername/graphql-crack-engine",
        "Tracker": "https://github.com/yourusername/graphql-crack-engine/issues",
    },
)