# policy_engine/loader.py
import json
import logging
import time
from pathlib import Path
from typing import List, Optional

from policy_engine.models import PolicyTemplate, PolicyRule

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / 'templates'

CACHE_TTL = 60  # seconds -- reload templates from disk every 60s


class PolicyLoader:
    """
    Loads policy templates from disk with a time-based TTL cache.

    Unlike lru_cache on an instance method (which is effectively infinite
    and never reloads), this cache expires every CACHE_TTL seconds,
    allowing hot-reload of policy changes without a full restart.

    Call invalidate_cache() to force immediate reload (e.g. after a
    policy template upload).
    """

    def __init__(self):
        self._cache: Optional[tuple] = None
        self._cache_loaded_at: float = 0.0

    def load_all_templates(self) -> tuple:
        """Load all policy templates from disk, cached with TTL."""
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_loaded_at) < CACHE_TTL:
            return self._cache

        templates = []
        json_files = sorted(TEMPLATES_DIR.glob('*.json'))
        for json_file in json_files:
            try:
                with open(json_file, encoding='utf-8') as f:
                    data = json.load(f)
                templates.append(PolicyTemplate(**data))
                logger.debug("Loaded template: %s", json_file.name)
            except Exception as e:
                logger.error("Failed to load template %s: %s", json_file.name, e)

        if not templates:
            logger.warning("No policy templates found in %s", TEMPLATES_DIR)

        self._cache = tuple(templates)
        self._cache_loaded_at = now
        return self._cache

    def get_rules_for_action(
        self,
        action_type: str,
        templates: Optional[tuple] = None,
    ) -> List[PolicyRule]:
        if templates is None:
            templates = self.load_all_templates()
        applicable_rules = []
        for template in templates:
            for rule in template.rules:
                if rule.action_type == action_type:
                    applicable_rules.append(rule)
        return applicable_rules

    def invalidate_cache(self):
        """Force immediate reload on next call. Use after uploading new templates."""
        self._cache = None
        self._cache_loaded_at = 0.0
        logger.info("Policy template cache invalidated -- will reload on next request")


policy_loader = PolicyLoader()
