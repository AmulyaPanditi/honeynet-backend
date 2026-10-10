import os
import json
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class TechniqueCatalogItem(BaseModel):
    technique_id: str = Field(..., description="Official MITRE ATT&CK technique identifier")
    name: str = Field(..., description="Official technique name")
    tactics: List[str] = Field(..., description="Applicable MITRE ATT&CK tactics")
    description: str = Field(..., description="Authoritative MITRE description")
    applicable_event_evidence: str = Field(..., description="Telemetry event conditions supporting this mapping")
    data_source_requirements: List[str] = Field(default_factory=list, description="Required MITRE data sources")
    mapping_rule_id: str = Field(..., description="Deterministic rule identifier")

CATALOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_catalog.json")

_CATALOG_CACHE: Optional[Dict[str, TechniqueCatalogItem]] = None

def load_mitre_catalog() -> Dict[str, TechniqueCatalogItem]:
    """
    Loads and caches the authoritative MITRE ATT&CK technique catalog from disk.
    """
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE

    if not os.path.exists(CATALOG_PATH):
        raise FileNotFoundError(f"MITRE catalog file not found at {CATALOG_PATH}")

    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    catalog = {}
    for item in data:
        cat_item = TechniqueCatalogItem(**item)
        catalog[cat_item.technique_id] = cat_item

    _CATALOG_CACHE = catalog
    return _CATALOG_CACHE

def get_technique_from_catalog(technique_id: str) -> Optional[TechniqueCatalogItem]:
    """
    Looks up a specific technique in the catalog by its identifier.
    """
    catalog = load_mitre_catalog()
    return catalog.get(technique_id)

def list_all_catalog_techniques() -> List[TechniqueCatalogItem]:
    """
    Returns all catalog items sorted by technique ID.
    """
    catalog = load_mitre_catalog()
    return list(catalog.values())
