"""
Unit tests for Orchestrator module.

Run with: pytest tests/unit/test_orchestrator.py -v
"""

import pytest
import asyncio
from src.vanguard.core.orchestrator import Orchestrator, TaskStatus, ScanTask


class TestOrchestrator:
    """Test suite for Orchestrator class"""

    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self):
        """Test orchestrator initializes correctly"""
        orchestrator = Orchestrator(
            target="https://example.com",
            max_concurrent_crawlers=2,
            max_concurrent_scanners=3,
        )

        assert orchestrator.target == "https://example.com"
        assert orchestrator.max_concurrent_crawlers == 2
        assert orchestrator.max_concurrent_scanners == 3
        assert orchestrator.is_running is False
        assert orchestrator.scan_id is None

    @pytest.mark.asyncio
    async def test_observer_pattern(self):
        """Test observer subscription and notification"""
        orchestrator = Orchestrator(target="https://example.com")

        events_received = []

        def test_observer(event, data):
            events_received.append((event, data))

        orchestrator.subscribe(test_observer)

        # Trigger notification
        orchestrator._notify_observers("test_event", {"key": "value"})

        assert len(events_received) == 1
        assert events_received[0][0] == "test_event"
        assert events_received[0][1]["key"] == "value"

    @pytest.mark.asyncio
    async def test_get_status(self):
        """Test status reporting"""
        orchestrator = Orchestrator(target="https://example.com")

        status = orchestrator.get_status()

        assert "scan_id" in status
        assert "is_running" in status
        assert "queues" in status
        assert "tasks" in status

    def test_task_status_enum(self):
        """Test TaskStatus enum values"""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
