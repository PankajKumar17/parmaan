"""
Attack-Agnostic Evidence Architecture for PRAMAAN

This module implements the shared interface that every detector in the project
must plug into, ensuring all evidence follows a standardized format regardless
of what attack type it targets.

Evidence Provider → Finding → Evidence → Correlation → Decision
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
import hashlib


class Modality(Enum):
    """Multi-Modal Evidence Formalization - each piece of evidence must declare its modality"""
    PIXEL = "PIXEL"
    EMBEDDING = "EMBEDDING"
    ANNOTATION = "ANNOTATION"
    ACTIVATION = "ACTIVATION"
    BEHAVIORAL = "BEHAVIORAL"


@dataclass
class Evidence:
    """A single piece of evidence with its own modality tag for grouping by the Correlation Engine"""
    content: str
    modality: Modality


@dataclass
class Finding:
    """
    Standard finding schema - all detectors must produce findings with these exact fields.
    Severity and confidence are tracked separately and never collapsed into one number.
    """
    asset_id: str
    finding_type: str
    severity: float  # 0-1: how bad IF true
    confidence: float  # 0-1: how sure we are it's true (separate from severity)
    evidence: List[str]  # human-readable evidence strings
    modality: Modality
    provenance: Dict[str, Any]  # {detector_id, version, input_hashes: list[str], config_hash: str}
    recommended_action: str  # "accept" | "review" | "quarantine"
    quarantine_scope: Optional[str] = None  # "sample" | "batch" | "contributor" | "model" | "inference_record"
    access_assumptions: str = "black_box"  # "white_box" | "gray_box" | "black_box"
    counter_evidence: List[str] = field(default_factory=list)  # evidence AGAINST this finding


class EvidenceProvider(ABC):
    """
    Abstract base class that every detector must implement.
    Each provider must declare detector_id and version which get embedded in every Finding.
    """
    
    def __init__(self, detector_id: str, version: str = "1.0.0"):
        self.detector_id = detector_id
        self.version = version
    
    @abstractmethod
    def analyze(self, asset: Any) -> List[Finding]:
        """
        Analyze an asset and return a list of findings.
        
        Args:
            asset: The asset to analyze (could be a file path, model object, dataset, etc.)
            
        Returns:
            List[Finding]: List of findings produced by this detector
        """
        pass
    
    def _create_provenance(self, input_hashes: List[str], config_hash: str) -> Dict[str, Any]:
        """
        Helper method to create provenance dict for findings.
        
        Args:
            input_hashes: List of hashes of input data/assets used
            config_hash: Hash of the configuration used for this analysis
            
        Returns:
            Dict containing provenance information
        """
        return {
            "detector_id": self.detector_id,
            "version": self.version,
            "input_hashes": input_hashes,
            "config_hash": config_hash
        }


# Example usage documentation:
"""
Every detector in the project should follow this pattern:

class MyDetector(EvidenceProvider):
    def __init__(self):
        super().__init__(detector_id="my_detector", version="1.0.0")
    
    def analyze(self, asset) -> List[Finding]:
        # Analysis logic here
        finding = Finding(
            asset_id="some_asset_id",
            finding_type="my_finding_type",
            severity=0.8,
            confidence=0.9,
            evidence=["Evidence string 1", "Evidence string 2"],
            modality=Modality.PIXEL,
            provenance=self._create_provenance(["input_hash_1"], "config_hash"),
            recommended_action="review",
            quarantine_scope="batch",
            access_assumptions="black_box",
            counter_evidence=["Counter evidence if any"]
        )
        return [finding]
"""