"""
Orchestrator - Central coordinator for crawling, scanning, and verification tasks.

This module implements the producer-consumer pattern with async task queues
to manage the entire vulnerability scanning pipeline.

Design Pattern: Producer-Consumer + Observer
Reference: @docs/ai-context/architecture.md
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import structlog


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanTask:
    """Represents a single scan task"""
    task_id: str
    target_url: str
    task_type: str  # 'crawl', 'scan', 'verify'
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class Orchestrator:
    """
    Central coordinator for the vulnerability scanning pipeline.

    Responsibilities:
    1. Manage task queues (crawling, scanning, verification)
    2. Coordinate between different modules
    3. Handle state persistence
    4. Monitor progress and errors

    Example:
        >>> orchestrator = Orchestrator(target="https://example.com")
        >>> await orchestrator.start()
        >>> results = await orchestrator.get_results()
    """

    def __init__(
        self,
        target: str,
        max_concurrent_crawlers: int = 2,
        max_concurrent_scanners: int = 3,
        max_concurrent_verifiers: int = 1,
    ):
        """
        Initialize the orchestrator.

        Args:
            target: Target URL to scan
            max_concurrent_crawlers: Number of concurrent crawler workers
            max_concurrent_scanners: Number of concurrent scanner workers
            max_concurrent_verifiers: Number of concurrent verifier workers
        """
        self.target = target
        self.max_concurrent_crawlers = max_concurrent_crawlers
        self.max_concurrent_scanners = max_concurrent_scanners
        self.max_concurrent_verifiers = max_concurrent_verifiers

        # Task queues (Producer-Consumer pattern)
        self.endpoint_queue: asyncio.Queue = asyncio.Queue()
        self.vulnerability_queue: asyncio.Queue = asyncio.Queue()
        self.result_queue: asyncio.Queue = asyncio.Queue()

        # State tracking
        self.tasks: Dict[str, ScanTask] = {}
        self.is_running = False
        self.scan_id: Optional[str] = None

        # Structured logging
        self.logger = structlog.get_logger(__name__)

        # Observer pattern - callbacks
        self.observers: List[callable] = []

    def subscribe(self, observer: callable):
        """
        Subscribe to orchestrator events (Observer pattern).

        Args:
            observer: Callback function for events
        """
        self.observers.append(observer)
        self.logger.info("observer_subscribed", observer=observer.__name__)

    def _notify_observers(self, event: str, data: Dict[str, Any]):
        """Notify all observers of an event"""
        for observer in self.observers:
            try:
                observer(event, data)
            except Exception as e:
                self.logger.error("observer_error", observer=observer.__name__, error=str(e))

    async def start(self) -> str:
        """
        Start the orchestration process.

        Returns:
            Scan ID for tracking
        """
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.is_running = True

        self.logger.info(
            "scan_started",
            scan_id=self.scan_id,
            target=self.target,
            config={
                "crawlers": self.max_concurrent_crawlers,
                "scanners": self.max_concurrent_scanners,
                "verifiers": self.max_concurrent_verifiers,
            }
        )

        # Notify observers
        self._notify_observers("scan_started", {"scan_id": self.scan_id, "target": self.target})

        # Create worker tasks
        async with asyncio.TaskGroup() as tg:
            # Crawler workers
            for i in range(self.max_concurrent_crawlers):
                tg.create_task(self._crawl_worker(i))

            # Scanner workers
            for i in range(self.max_concurrent_scanners):
                tg.create_task(self._scan_worker(i))

            # Verifier workers
            for i in range(self.max_concurrent_verifiers):
                tg.create_task(self._verify_worker(i))

        return self.scan_id

    async def _crawl_worker(self, worker_id: int):
        """
        Crawler worker that processes crawling tasks.

        Args:
            worker_id: Worker identifier
        """
        self.logger.info("crawl_worker_started", worker_id=worker_id)

        while self.is_running:
            try:
                # TODO: Implement actual crawling logic in Week 1
                # For now, just placeholder
                await asyncio.sleep(1)

                # Example: Put discovered endpoints into queue
                # endpoint = await self.crawler.crawl(self.target)
                # await self.endpoint_queue.put(endpoint)

            except Exception as e:
                self.logger.error("crawl_worker_error", worker_id=worker_id, error=str(e))

    async def _scan_worker(self, worker_id: int):
        """
        Scanner worker that processes vulnerability scanning tasks.

        Args:
            worker_id: Worker identifier
        """
        self.logger.info("scan_worker_started", worker_id=worker_id)

        while self.is_running:
            try:
                # Get endpoint from queue (Consumer)
                endpoint = await self.endpoint_queue.get()

                # TODO: Implement actual scanning logic in Week 2-3
                # vulnerability = await self.scanner.scan(endpoint)
                # if vulnerability:
                #     await self.vulnerability_queue.put(vulnerability)

                self.endpoint_queue.task_done()

            except Exception as e:
                self.logger.error("scan_worker_error", worker_id=worker_id, error=str(e))

    async def _verify_worker(self, worker_id: int):
        """
        Verification worker that processes POC verification tasks.

        Args:
            worker_id: Worker identifier
        """
        self.logger.info("verify_worker_started", worker_id=worker_id)

        while self.is_running:
            try:
                # Get vulnerability from queue
                vulnerability = await self.vulnerability_queue.get()

                # TODO: Implement actual verification logic in Week 4
                # verified = await self.verifier.verify(vulnerability)
                # if verified:
                #     await self.result_queue.put(verified)

                self.vulnerability_queue.task_done()

            except Exception as e:
                self.logger.error("verify_worker_error", worker_id=worker_id, error=str(e))

    async def stop(self):
        """Stop the orchestration process gracefully"""
        self.logger.info("stopping_orchestrator", scan_id=self.scan_id)
        self.is_running = False

        # Wait for queues to be processed
        await self.endpoint_queue.join()
        await self.vulnerability_queue.join()
        await self.result_queue.join()

        self.logger.info("orchestrator_stopped", scan_id=self.scan_id)
        self._notify_observers("scan_stopped", {"scan_id": self.scan_id})

    async def get_results(self) -> List[Dict[str, Any]]:
        """
        Get scan results.

        Returns:
            List of vulnerability results
        """
        results = []
        while not self.result_queue.empty():
            results.append(await self.result_queue.get())

        return results

    def get_status(self) -> Dict[str, Any]:
        """
        Get current orchestrator status.

        Returns:
            Status dictionary
        """
        return {
            "scan_id": self.scan_id,
            "is_running": self.is_running,
            "queues": {
                "endpoints": self.endpoint_queue.qsize(),
                "vulnerabilities": self.vulnerability_queue.qsize(),
                "results": self.result_queue.qsize(),
            },
            "tasks": len(self.tasks),
        }
