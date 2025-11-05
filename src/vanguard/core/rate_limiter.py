"""
Adaptive Rate Limiter - Intelligent request throttling to avoid WAF/IDS detection.

This module implements an adaptive rate limiting algorithm that adjusts delays
based on server responses and error rates.

Design Pattern: Adaptive Control System
Reference: @docs/ai-context/security.md:210-252
"""

import asyncio
import random
import time
from typing import Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

import structlog


class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    pass


class ScanAbortedError(Exception):
    """Raised when scan must be aborted due to too many errors"""
    pass


@dataclass
class RateLimitConfig:
    """Configuration for rate limiter"""
    base_delay: float = 3.0  # Base delay between requests (seconds)
    min_delay: float = 2.0   # Minimum delay allowed
    max_delay: float = 10.0  # Maximum delay allowed
    jitter_range: float = 0.5  # Random jitter (+/- seconds)
    max_errors: int = 10     # Maximum errors before aborting
    speedup_threshold: int = 10  # Success count before trying to speed up
    speedup_factor: float = 0.95  # Factor to multiply delay when speeding up
    slowdown_factor_429: float = 2.0  # Factor for 429 errors
    slowdown_factor_5xx: float = 1.5  # Factor for 5xx errors


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts delays based on server responses.

    Key features:
    1. Adaptive throttling - speeds up if server is fast, slows down on errors
    2. Jitter - adds randomness to mimic human behavior
    3. Emergency stop - aborts if too many errors
    4. Normal distribution delays - more realistic than uniform random

    Example:
        >>> limiter = AdaptiveRateLimiter()
        >>> await limiter.wait()  # Wait before next request
        >>> limiter.on_success(response_time=0.5)
        >>> limiter.on_error(status_code=429)
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize the rate limiter.

        Args:
            config: Rate limit configuration (uses defaults if None)
        """
        self.config = config or RateLimitConfig()
        self.current_delay = self.config.base_delay
        self.error_count = 0
        self.success_count = 0
        self.request_count = 0
        self.last_request_time: Optional[float] = None

        self.logger = structlog.get_logger(__name__)

        self.logger.info(
            "rate_limiter_initialized",
            base_delay=self.config.base_delay,
            min_delay=self.config.min_delay,
            max_delay=self.config.max_delay,
        )

    async def wait(self):
        """
        Wait before next request with adaptive delay + jitter.

        This method implements the core rate limiting logic:
        1. Calculate adaptive delay based on current conditions
        2. Add random jitter for human-like behavior
        3. Ensure delay is within min/max bounds
        4. Use normal distribution for more realistic timing
        """
        # Add jitter (uniform random)
        jitter = random.uniform(-self.config.jitter_range, self.config.jitter_range)
        delay = self.current_delay + jitter

        # Clamp to min/max bounds
        delay = max(self.config.min_delay, min(self.config.max_delay, delay))

        # Add small random variation using normal distribution (more human-like)
        delay = random.normalvariate(mu=delay, sigma=0.3)
        delay = max(self.config.min_delay, delay)

        self.logger.debug(
            "rate_limit_wait",
            delay=f"{delay:.2f}s",
            current_delay=f"{self.current_delay:.2f}s",
            error_count=self.error_count,
            success_count=self.success_count,
        )

        await asyncio.sleep(delay)

        self.last_request_time = time.time()
        self.request_count += 1

    def on_success(self, response_time: float):
        """
        Record successful request and potentially speed up.

        Args:
            response_time: Server response time in seconds

        The rate limiter will gradually speed up if:
        1. Server is responding quickly (< 1 second)
        2. We have a streak of successful requests
        """
        self.success_count += 1
        self.error_count = 0  # Reset error count on success

        # If server is fast and we have enough successes, try speeding up
        if response_time < 1.0 and self.success_count >= self.config.speedup_threshold:
            old_delay = self.current_delay
            self.current_delay = max(
                self.config.base_delay,
                self.current_delay * self.config.speedup_factor
            )

            if old_delay != self.current_delay:
                self.logger.info(
                    "rate_limit_speedup",
                    old_delay=f"{old_delay:.2f}s",
                    new_delay=f"{self.current_delay:.2f}s",
                    response_time=f"{response_time:.2f}s",
                )

    def on_error(self, status_code: int):
        """
        Record error and slow down accordingly.

        Args:
            status_code: HTTP status code of the error

        Raises:
            ScanAbortedError: If too many errors occurred
        """
        self.error_count += 1
        self.success_count = 0  # Reset success count on error

        old_delay = self.current_delay

        # Different slowdown factors for different errors
        if status_code == 429:  # Too Many Requests
            self.current_delay *= self.config.slowdown_factor_429
            self.logger.warning(
                "rate_limit_hit",
                status_code=429,
                old_delay=f"{old_delay:.2f}s",
                new_delay=f"{self.current_delay:.2f}s",
            )

        elif status_code >= 500:  # Server errors
            self.current_delay *= self.config.slowdown_factor_5xx
            self.logger.warning(
                "server_error_detected",
                status_code=status_code,
                old_delay=f"{old_delay:.2f}s",
                new_delay=f"{self.current_delay:.2f}s",
            )

        # Clamp to max delay
        self.current_delay = min(self.config.max_delay, self.current_delay)

        # Emergency stop if too many errors
        if self.error_count >= self.config.max_errors:
            self.logger.critical(
                "scan_aborted",
                reason="too_many_errors",
                error_count=self.error_count,
                max_errors=self.config.max_errors,
            )
            raise ScanAbortedError(
                f"Too many errors ({self.error_count}), aborting scan"
            )

    async def emergency_backoff(self):
        """
        Emergency backoff when WAF block is detected.

        Implements exponential backoff with a much longer delay.
        """
        backoff_delay = self.config.max_delay * 2
        self.logger.critical(
            "emergency_backoff",
            delay=f"{backoff_delay:.2f}s",
            reason="waf_block_detected",
        )
        await asyncio.sleep(backoff_delay)

    def reset(self):
        """Reset the rate limiter to initial state"""
        self.current_delay = self.config.base_delay
        self.error_count = 0
        self.success_count = 0
        self.request_count = 0
        self.last_request_time = None

        self.logger.info("rate_limiter_reset")

    def get_stats(self) -> dict:
        """
        Get rate limiter statistics.

        Returns:
            Dictionary with current statistics
        """
        return {
            "current_delay": f"{self.current_delay:.2f}s",
            "error_count": self.error_count,
            "success_count": self.success_count,
            "request_count": self.request_count,
            "config": {
                "base_delay": self.config.base_delay,
                "min_delay": self.config.min_delay,
                "max_delay": self.config.max_delay,
            }
        }
