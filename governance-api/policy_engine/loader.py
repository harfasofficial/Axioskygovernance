# policy_engine/loader.py
import json
import logging
import time
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from policy_engine.models import PolicyTemplate, PolicyRule

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / 'templates'

# In-memory cache with TTL
_template_cache: dict = {}
_cache_ttl = 60  # seconds


class PolicyLoader:

    @lru_cache(maxsize=1)
    def load_all_templates(self) -> tuple:
        """Load all policy templates from disk with LRU caching."""
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

        return tuple(templates)

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
        """Clear the template cache. Useful for reloading after updates."""
        self.load_all_templates.cache_clear()


policy_loader = PolicyLoader()
