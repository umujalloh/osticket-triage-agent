import ipaddress
import re
from enum import Enum
from typing import Optional
from pydantic import BaseModel, field_validator

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

HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,64}\$?$")

class TicketClassification(BaseModel):
    category: Category
    severity: Severity
    confidence: Confidence
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v):
        if v is None:
            return v
        if not HOSTNAME_PATTERN.match(v):
            return None
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None:
            return v
        if not USERNAME_PATTERN.match(v):
            return None
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v):
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            return None
        return v
