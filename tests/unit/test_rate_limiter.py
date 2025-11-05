"""
Unit tests for AdaptiveRateLimiter module.

Run with: pytest tests/unit/test_rate_limiter.py -v
"""

import pytest
import asyncio
from src.vanguard.core.rate_limiter import (
    AdaptiveRateLimiter,
    RateLimitConfig,
    ScanAbortedError,
)


class TestAdaptiveRateLimiter:
    """Test suite for AdaptiveRateLimiter class"""

    def test_initialization_with_defaults(self):
        """Test rate limiter initializes with default config"""
        limiter = AdaptiveRateLimiter()

        assert limiter.current_delay == 3.0
        assert limiter.error_count == 0
        assert limiter.success_count == 0
        assert limiter.request_count == 0

    def test_initialization_with_custom_config(self):
        """Test rate limiter initializes with custom config"""
        config = RateLimitConfig(
            base_delay=5.0,
            min_delay=3.0,
            max_delay=15.0,
        )
        limiter = AdaptiveRateLimiter(config=config)

        assert limiter.current_delay == 5.0
        assert limiter.config.min_delay == 3.0
        assert limiter.config.max_delay == 15.0

    @pytest.mark.asyncio
    async def test_wait_increments_request_count(self):
        """Test wait() increments request count"""
        config = RateLimitConfig(base_delay=0.1, min_delay=0.1)  # Fast for testing
        limiter = AdaptiveRateLimiter(config=config)

        await limiter.wait()

        assert limiter.request_count == 1
        assert limiter.last_request_time is not None

    def test_on_success_resets_error_count(self):
        """Test on_success() resets error count"""
        limiter = AdaptiveRateLimiter()
        limiter.error_count = 5

        limiter.on_success(response_time=0.5)

        assert limiter.error_count == 0
        assert limiter.success_count == 1

    def test_on_success_speeds_up_after_threshold(self):
        """Test rate limiter speeds up after success threshold"""
        config = RateLimitConfig(speedup_threshold=5, speedup_factor=0.9)
        limiter = AdaptiveRateLimiter(config=config)

        # Simulate 10 fast successes
        for _ in range(10):
            limiter.on_success(response_time=0.5)

        # Delay should have decreased
        assert limiter.current_delay < config.base_delay

    def test_on_error_429_slows_down(self):
        """Test 429 error causes slowdown"""
        limiter = AdaptiveRateLimiter()
        initial_delay = limiter.current_delay

        limiter.on_error(status_code=429)

        assert limiter.current_delay > initial_delay
        assert limiter.error_count == 1
        assert limiter.success_count == 0

    def test_on_error_5xx_slows_down(self):
        """Test 5xx errors cause slowdown"""
        limiter = AdaptiveRateLimiter()
        initial_delay = limiter.current_delay

        limiter.on_error(status_code=500)

        assert limiter.current_delay > initial_delay
        assert limiter.error_count == 1

    def test_on_error_aborts_after_max_errors(self):
        """Test scanner aborts after max errors"""
        config = RateLimitConfig(max_errors=3)
        limiter = AdaptiveRateLimiter(config=config)

        # First 2 errors should not abort
        limiter.on_error(status_code=429)
        limiter.on_error(status_code=429)

        # 3rd error should abort
        with pytest.raises(ScanAbortedError):
            limiter.on_error(status_code=429)

    def test_reset(self):
        """Test reset() restores initial state"""
        limiter = AdaptiveRateLimiter()

        # Modify state
        limiter.error_count = 5
        limiter.success_count = 10
        limiter.request_count = 20
        limiter.current_delay = 10.0

        # Reset
        limiter.reset()

        # Verify reset
        assert limiter.error_count == 0
        assert limiter.success_count == 0
        assert limiter.request_count == 0
        assert limiter.current_delay == limiter.config.base_delay

    def test_get_stats(self):
        """Test get_stats() returns correct information"""
        limiter = AdaptiveRateLimiter()
        limiter.error_count = 2
        limiter.success_count = 5
        limiter.request_count = 7

        stats = limiter.get_stats()

        assert "current_delay" in stats
        assert stats["error_count"] == 2
        assert stats["success_count"] == 5
        assert stats["request_count"] == 7


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
