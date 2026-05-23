"""SentinelX IDS - Rule Loader.

Loads, validates, and manages Sigma-like YAML detection rules from disk.
Supports hot-reload, schema validation, and pre-compiled regex patterns
for high-throughput matching.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("sentinelx.rule_loader")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

_VALID_SEVERITIES: frozenset[str] = frozenset({"info", "low", "medium", "high", "critical"})

_REQUIRED_FIELDS: frozenset[str] = frozenset({
    "id", "name", "severity", "detection",
})


@dataclass(slots=True)
class CompiledPattern:
    """A single compiled detection pattern.

    Attributes:
        field_name: The event field to match against (e.g. ``message``).
        regex_source: The original regex string from the YAML rule.
        compiled: The pre-compiled ``re.Pattern`` object.
    """

    field_name: str
    regex_source: str
    compiled: re.Pattern[str]


@dataclass(slots=True)
class Rule:
    """Representation of a single Sigma-like detection rule.

    Attributes:
        id: Unique rule identifier (e.g. ``SX-1001``).
        name: Human-readable rule name.
        description: Detailed description of what the rule detects.
        severity: Canonical severity — ``info``, ``low``, ``medium``,
                  ``high``, or ``critical``.
        category: MITRE ATT&CK tactic or custom category.
        mitre_technique: MITRE ATT&CK technique ID (e.g. ``T1110``).
        mitre_tactic: MITRE ATT&CK tactic name.
        detection: Raw detection dict from YAML (condition + patterns).
        enabled: Whether the rule is currently active.
        compiled_patterns: Pre-compiled regex patterns for fast matching.
        threshold: Optional threshold configuration.
        log_source: Expected log source type (``syslog``, ``windows_event``, etc.).
        tags: Arbitrary tags for filtering.
        author: Rule author.
        date: Rule creation / last-modified date string.
        file_path: Path to the YAML file this rule was loaded from.
    """

    id: str
    name: str
    description: str
    severity: str
    category: str
    mitre_technique: str
    mitre_tactic: str
    detection: dict[str, Any]
    enabled: bool
    compiled_patterns: list[CompiledPattern]
    threshold: dict[str, Any] = field(default_factory=dict)
    log_source: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = ""
    date: str = ""
    file_path: str = ""


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

class RuleLoader:
    """Loads and manages Sigma-like YAML detection rules.

    Usage::

        loader = RuleLoader()
        rules = loader.load_rules_from_directory("./rules")
        rule = loader.get_rule("SX-1001")
        loader.reload_rules()  # hot-reload
    """

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._rules_directory: str = ""
        self._load_errors: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_rules_from_directory(self, rules_path: str) -> list[Rule]:
        """Recursively discover and load all ``.yml`` / ``.yaml`` rule files.

        Args:
            rules_path: Path to the rules directory.

        Returns:
            List of successfully loaded ``Rule`` instances.
        """
        self._rules_directory = str(rules_path)
        self._rules.clear()
        self._load_errors.clear()

        rules_dir = Path(rules_path)
        if not rules_dir.is_dir():
            logger.error("Rules directory does not exist: %s", rules_path)
            return []

        yaml_files = sorted(
            p for p in rules_dir.rglob("*")
            if p.suffix.lower() in (".yml", ".yaml") and p.is_file()
        )

        loaded: list[Rule] = []
        for yaml_file in yaml_files:
            rule = self._load_rule_file(yaml_file)
            if rule is not None:
                self._rules[rule.id] = rule
                loaded.append(rule)

        logger.info(
            "Loaded %d rules from %s (%d errors)",
            len(loaded),
            rules_path,
            len(self._load_errors),
        )
        return loaded

    def get_rule(self, rule_id: str) -> Rule | None:
        """Retrieve a rule by its unique ID.

        Args:
            rule_id: The rule identifier (e.g. ``SX-1001``).

        Returns:
            The ``Rule`` if found, otherwise ``None``.
        """
        return self._rules.get(rule_id)

    def get_all_rules(self) -> list[Rule]:
        """Return all loaded rules."""
        return list(self._rules.values())

    def get_enabled_rules(self) -> list[Rule]:
        """Return only enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def reload_rules(self) -> list[Rule]:
        """Hot-reload rules from the previously configured directory.

        Returns:
            List of freshly loaded rules.

        Raises:
            RuntimeError: If no directory was previously configured.
        """
        if not self._rules_directory:
            raise RuntimeError("No rules directory configured. Call load_rules_from_directory first.")
        logger.info("Hot-reloading rules from %s", self._rules_directory)
        return self.load_rules_from_directory(self._rules_directory)

    @property
    def load_errors(self) -> list[dict[str, str]]:
        """Return a list of errors encountered during the last load."""
        return list(self._load_errors)

    @property
    def rules_directory(self) -> str:
        """Return the currently configured rules directory."""
        return self._rules_directory

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_rule_file(self, path: Path) -> Rule | None:
        """Load and validate a single YAML rule file."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)

            if not isinstance(data, dict):
                self._record_error(str(path), "File does not contain a YAML mapping")
                return None

            # Validate required fields
            missing = _REQUIRED_FIELDS - set(data.keys())
            if missing:
                self._record_error(str(path), f"Missing required fields: {missing}")
                return None

            # Validate severity
            severity = str(data.get("severity", "info")).lower()
            if severity not in _VALID_SEVERITIES:
                self._record_error(str(path), f"Invalid severity '{severity}'")
                severity = "info"

            # Parse detection block
            detection = data.get("detection", {})
            compiled_patterns = self._compile_detection_patterns(detection, str(path))

            # Parse threshold
            threshold = data.get("threshold", {})

            # Build Rule
            rule = Rule(
                id=str(data["id"]),
                name=str(data["name"]),
                description=str(data.get("description", "")),
                severity=severity,
                category=str(data.get("category", "")),
                mitre_technique=str(data.get("mitre_technique", "")),
                mitre_tactic=str(data.get("mitre_tactic", "")),
                detection=detection,
                enabled=bool(data.get("enabled", True)),
                compiled_patterns=compiled_patterns,
                threshold=threshold if isinstance(threshold, dict) else {},
                log_source=str(data.get("log_source", "")),
                tags=list(data.get("tags", [])),
                author=str(data.get("author", "")),
                date=str(data.get("date", "")),
                file_path=str(path),
            )

            logger.debug("Loaded rule %s (%s) from %s", rule.id, rule.name, path)
            return rule

        except yaml.YAMLError as exc:
            self._record_error(str(path), f"YAML parse error: {exc}")
            return None
        except Exception as exc:
            self._record_error(str(path), f"Unexpected error: {exc}")
            return None

    def _compile_detection_patterns(
        self,
        detection: dict[str, Any],
        file_path: str,
    ) -> list[CompiledPattern]:
        """Compile regex patterns from the detection block."""
        compiled: list[CompiledPattern] = []
        patterns = detection.get("patterns", [])

        if not isinstance(patterns, list):
            self._record_error(file_path, "detection.patterns is not a list")
            return compiled

        for i, pattern_def in enumerate(patterns):
            if not isinstance(pattern_def, dict):
                self._record_error(file_path, f"Pattern {i} is not a mapping")
                continue

            field_name = str(pattern_def.get("field", "message"))
            regex_source = str(pattern_def.get("regex", ""))

            if not regex_source:
                self._record_error(file_path, f"Pattern {i} has empty regex")
                continue

            try:
                compiled_re = re.compile(regex_source)
                compiled.append(CompiledPattern(
                    field_name=field_name,
                    regex_source=regex_source,
                    compiled=compiled_re,
                ))
            except re.error as exc:
                self._record_error(
                    file_path,
                    f"Pattern {i} regex compile error: {exc} (regex: {regex_source!r})",
                )

        return compiled

    def _record_error(self, file_path: str, message: str) -> None:
        """Record a load error for later inspection."""
        error = {"file": file_path, "error": message}
        self._load_errors.append(error)
        logger.warning("Rule load error in %s: %s", file_path, message)
