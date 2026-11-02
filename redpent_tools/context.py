"""Shared runtime context handed to every tool: config + guard + auditor + runner.

Tools receive this instead of reaching for globals, which keeps them unit-testable.
"""
from __future__ import annotations

from dataclasses import dataclass

from .audit import Auditor
from .config import Config, load_config
from .runner import Runner
from .scope import ScopeGuard


@dataclass
class ReconContext:
    config: Config
    guard: ScopeGuard
    auditor: Auditor
    runner: Runner

    @classmethod
    def create(cls) -> "ReconContext":
        cfg = load_config()
        return cls(
            config=cfg,
            guard=ScopeGuard(cfg),
            auditor=Auditor(cfg),
            runner=Runner(cfg),
        )
