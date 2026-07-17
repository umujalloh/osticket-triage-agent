from enum import Enum
from pydantic import BaseModel

class Category(str, Enum):
    security_incident = "security_incident"
    security_question = "security_question"
    it_support = "it_support"
    unclear = "unclear"

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"

class Confidence(str, Enum):
    high_confidence = "high_confidence"
    low_confidence = "low_confidence"

class TicketClassification(BaseModel):
    category: Category
    severity: Severity
    confidence: Confidence
