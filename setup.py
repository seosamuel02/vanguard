"""
Setup configuration for VANGUARD package.
"""

from setuptools import setup, find_packages

setup(
    name="vanguard",
    version="1.0.0",
    description="Bug Bounty Automation Scanner",
    author="VANGUARD Team",
    python_requires=">=3.11",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "playwright>=1.40.0",
        "crawlee>=0.6.0",
        "aiohttp>=3.9.1",
        # "aiohttp-ratelimit>=0.8.0",  # Not available, using custom rate limiter
        "structlog>=23.2.0",
        "click>=8.1.7",
        "rich>=13.7.0",
        "pydantic>=2.5.2",
        "PyYAML>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.12.1",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "vanguard=main:cli",
        ],
    },
)
