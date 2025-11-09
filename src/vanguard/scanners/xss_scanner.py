"""
XSS Scanner - Cross-Site Scripting vulnerability detection.

This module integrates Dalfox and XSStrike for comprehensive XSS detection.
Dalfox is the primary engine, with XSStrike as a fallback.

Tools:
- Dalfox 2.9+: DOM-based detection, context-aware
- XSStrike 3.1+: Advanced polyglot payloads (backup)

Reference: @docs/ai-context/security.md (Non-destructive payloads)
"""

import asyncio
import json
import tempfile
import shutil
from typing import List, Optional, Dict, Any
from pathlib import Path

from .base_scanner import (
    BaseScanner,
    Vulnerability,
    VulnerabilityType,
    SeverityLevel,
    ScannerError,
    ScannerTimeoutError,
)


class XSSScanner(BaseScanner):
    """
    Cross-Site Scripting vulnerability scanner.

    Integrates Dalfox for XSS detection with non-destructive payloads
    and bug bounty compliance.

    Features:
    1. Reflected, Stored, DOM-based XSS detection
    2. Non-destructive payloads (console.log, no alert)
    3. Mandatory bug bounty headers
    4. JSON output parsing
    5. Confidence scoring

    Example:
        >>> scanner = XSSScanner(
        ...     dalfox_path="/usr/local/bin/dalfox",
        ...     mandatory_headers={"bugbounty": "[FindtheGap]..."}
        ... )
        >>> vulnerabilities = await scanner.scan(endpoint)
    """

    # Non-destructive XSS payloads (CRITICAL: Never use alert())
    # Reference: @docs/ai-context/security.md:3
    SAFE_PAYLOADS = [
        # Console logging (undetectable by WAF)
        "console.log('XSS_VANGUARD')",
        "console.warn('XSS_VANGUARD')",

        # DOM marker (no popup)
        "document.body.setAttribute('data-xss', 'VANGUARD')",

        # Image onerror (non-intrusive)
        '<img src=x onerror="console.log(\'XSS_VANGUARD\')">',

        # SVG-based (modern browsers)
        '<svg onload="console.log(\'XSS_VANGUARD\')">',
    ]

    def __init__(
        self,
        dalfox_path: str = "dalfox",
        xsstrike_path: Optional[str] = None,
        rate_limiter: Optional[Any] = None,
        mandatory_headers: Optional[Dict[str, str]] = None,
        timeout: int = 60,
        enabled: bool = True,
    ):
        """
        Initialize XSS scanner.

        Args:
            dalfox_path: Path to dalfox binary (default: "dalfox" in PATH)
            xsstrike_path: Path to xsstrike.py (optional, for fallback)
            rate_limiter: Rate limiter instance
            mandatory_headers: Headers to include (bug bounty compliance)
            timeout: Timeout for each scan in seconds
            enabled: Whether scanner is enabled
        """
        super().__init__(
            scanner_name="XSSScanner",
            rate_limiter=rate_limiter,
            enabled=enabled,
        )

        self.dalfox_path = dalfox_path
        self.xsstrike_path = xsstrike_path
        self.timeout = timeout

        # Mandatory headers for bug bounty compliance
        # Reference: @docs/ai-context/security.md:2
        self.mandatory_headers = mandatory_headers or {
            "bugbounty": "[FindtheGap] Automated Security Scanner - Contact: your@email.com",
            "User-Agent": "VANGUARD/1.0 (Bug Bounty Scanner)",
        }

        # Check if tools are installed
        self._check_tools()

    def _check_tools(self):
        """Check if Dalfox is installed and accessible"""
        dalfox_available = shutil.which(self.dalfox_path) is not None

        if not dalfox_available:
            self.logger.warning(
                "dalfox_not_found",
                path=self.dalfox_path,
                message="Dalfox not found. Install with: go install github.com/hahwul/dalfox/v2@latest"
            )
            # Don't raise error - allow graceful degradation
            self.enabled = False
        else:
            self.logger.info("dalfox_found", path=shutil.which(self.dalfox_path))

    async def scan(self, endpoint) -> List[Vulnerability]:
        """
        Scan endpoint for XSS vulnerabilities.

        Args:
            endpoint: Endpoint object with URL and parameters

        Returns:
            List of XSS vulnerabilities (empty if none found)

        Raises:
            ScannerError: If scanning fails
        """
        if not self.enabled:
            self.logger.warning("xss_scanner_disabled")
            return []

        self.logger.info("scanning_xss", url=endpoint.url, method=endpoint.method)

        try:
            # Try Dalfox first (primary)
            vulnerabilities = await self._scan_with_dalfox(endpoint)

            # Fallback to XSStrike if Dalfox finds nothing and XSStrike is available
            if not vulnerabilities and self.xsstrike_path:
                self.logger.info("dalfox_found_nothing_trying_xsstrike", url=endpoint.url)
                vulnerabilities = await self._scan_with_xsstrike(endpoint)

            return vulnerabilities

        except asyncio.TimeoutError:
            raise ScannerTimeoutError(f"XSS scan timeout for {endpoint.url}")
        except Exception as e:
            raise ScannerError(f"XSS scan failed: {str(e)}")

    async def _scan_with_dalfox(self, endpoint) -> List[Vulnerability]:
        """
        Scan using Dalfox.

        Args:
            endpoint: Endpoint object

        Returns:
            List of vulnerabilities
        """
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as tmp_file:
            output_file = tmp_file.name

        try:
            # Build Dalfox command
            cmd = self._build_dalfox_command(endpoint, output_file)

            self.logger.debug("executing_dalfox", command=" ".join(cmd))

            # Execute Dalfox
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )

            # Parse results
            vulnerabilities = self._parse_dalfox_output(output_file, endpoint)

            self.logger.info(
                "dalfox_scan_complete",
                url=endpoint.url,
                found=len(vulnerabilities)
            )

            return vulnerabilities

        except asyncio.TimeoutError:
            self.logger.error("dalfox_timeout", url=endpoint.url)
            raise ScannerTimeoutError(f"Dalfox timeout: {endpoint.url}")

        except Exception as e:
            self.logger.error(
                "dalfox_failed",
                url=endpoint.url,
                error=str(e),
                exc_info=True
            )
            return []  # Graceful degradation

        finally:
            # Clean up temp file
            try:
                Path(output_file).unlink(missing_ok=True)
            except Exception:
                pass

    def _build_dalfox_command(self, endpoint, output_file: str) -> List[str]:
        """
        Build Dalfox command with security compliance.

        Args:
            endpoint: Endpoint to scan
            output_file: Path to JSON output file

        Returns:
            Command as list of strings
        """
        cmd = [
            self.dalfox_path,
            "url",
            endpoint.url,
            "--format", "json",
            "--output", output_file,
            "--silence",  # Reduce noise
            "--follow-redirects",  # Follow redirects
            "--skip-bav",  # Skip browser-based verification (we do this separately)
        ]

        # Add custom non-destructive payloads
        for payload in self.SAFE_PAYLOADS:
            cmd.extend(["--custom-payload", payload])

        # Add mandatory headers
        for key, value in self.mandatory_headers.items():
            cmd.extend(["--header", f"{key}: {value}"])

        # Add HTTP method if not GET
        if endpoint.method.upper() != "GET":
            cmd.extend(["--method", endpoint.method.upper()])

        return cmd

    def _parse_dalfox_output(
        self,
        output_file: str,
        endpoint
    ) -> List[Vulnerability]:
        """
        Parse Dalfox JSON output.

        Args:
            output_file: Path to JSON output
            endpoint: Original endpoint

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        try:
            output_path = Path(output_file)
            if not output_path.exists() or output_path.stat().st_size == 0:
                self.logger.debug("dalfox_empty_output", file=output_file)
                return []

            with open(output_file, 'r', encoding='utf-8') as f:
                results = json.load(f)

            # Dalfox output format: array of vulnerability objects
            for result in results:
                vuln = self._convert_dalfox_result(result, endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            self.logger.error("dalfox_json_parse_error", error=str(e))
        except Exception as e:
            self.logger.error(
                "dalfox_parse_failed",
                error=str(e),
                exc_info=True
            )

        return vulnerabilities

    def _convert_dalfox_result(
        self,
        result: Dict[str, Any],
        endpoint
    ) -> Optional[Vulnerability]:
        """
        Convert Dalfox result to Vulnerability object.

        Args:
            result: Dalfox JSON result
            endpoint: Original endpoint

        Returns:
            Vulnerability object or None
        """
        try:
            # Dalfox result fields:
            # - type: "XSS" or "REFLECTED-XSS", "STORED-XSS"
            # - poc: Proof of concept URL
            # - param: Vulnerable parameter
            # - payload: Injected payload
            # - evidence: Response evidence

            vuln_type_str = result.get("type", "").upper()
            if "STORED" in vuln_type_str:
                vuln_type = VulnerabilityType.XSS_STORED
            elif "DOM" in vuln_type_str:
                vuln_type = VulnerabilityType.XSS_DOM
            else:
                vuln_type = VulnerabilityType.XSS_REFLECTED

            # Calculate confidence based on evidence
            confidence = 0.8  # Dalfox is reliable
            if result.get("evidence"):
                confidence = 0.9

            return Vulnerability(
                vuln_type=vuln_type,
                url=endpoint.url,
                parameter=result.get("param"),
                severity=self._calculate_severity(result),
                confidence=confidence,
                payload=result.get("payload"),
                method=endpoint.method,
                evidence=result.get("evidence", "")[:500],  # Limit evidence size
                poc_url=result.get("poc"),
                scanner_name="Dalfox",
                verified=False,  # Will be verified by browser verifier
                description=f"{vuln_type.value.replace('_', ' ').title()} vulnerability detected",
                remediation="Sanitize user input and use Content Security Policy (CSP)",
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting",
                ],
            )

        except Exception as e:
            self.logger.error(
                "dalfox_conversion_failed",
                result=result,
                error=str(e)
            )
            return None

    def _calculate_severity(self, result: Dict[str, Any]) -> SeverityLevel:
        """
        Calculate severity level from Dalfox result.

        Args:
            result: Dalfox result

        Returns:
            Severity level
        """
        # XSS severity factors:
        # 1. Type (Stored > DOM > Reflected)
        # 2. Context (script context > attribute > comment)
        # 3. Bypass techniques used

        vuln_type = result.get("type", "").upper()

        if "STORED" in vuln_type:
            return SeverityLevel.HIGH  # Stored XSS is always high
        elif "DOM" in vuln_type:
            return SeverityLevel.MEDIUM  # DOM-based is medium-high
        else:
            return SeverityLevel.MEDIUM  # Reflected is medium

    async def _scan_with_xsstrike(self, endpoint) -> List[Vulnerability]:
        """
        Scan using XSStrike (fallback).

        Args:
            endpoint: Endpoint object

        Returns:
            List of vulnerabilities
        """
        # TODO: Implement XSStrike integration (Week 2, optional)
        # This is a backup scanner if Dalfox fails
        self.logger.info("xsstrike_not_implemented_yet")
        return []

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"XSSScanner("
            f"dalfox={self.dalfox_path}, "
            f"enabled={self.enabled}, "
            f"scanned={self.scanned_count}, "
            f"found={self.vulnerability_count})"
        )
