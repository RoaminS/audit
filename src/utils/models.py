# utils/models.py

from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import func # For database functions like current_timestamp
import datetime

# Base class for declarative models
Base = declarative_base()

class URL(Base):
    __tablename__ = 'urls'
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False, index=True)
    is_target = Column(Boolean, default=False) # True if this is the initial target URL
    # crawled_at = Column(DateTime, default=datetime.datetime.now) # Optional: when was this URL first crawled
    # last_scanned_at = Column(DateTime) # Optional: when was this URL last scanned

    def __repr__(self):
        return f"<URL(id={self.id}, url='{self.url}', is_target={self.is_target})>"

class DiscoveredEndpoint(Base):
    __tablename__ = 'discovered_endpoints'
    id = Column(Integer, primary_key=True)
    endpoint_hash = Column(String, unique=True, nullable=False, index=True) # Unique hash for the endpoint
    url = Column(String, nullable=False, index=True)
    method = Column(String(10), default='GET') # e.g., GET, POST, PUT, DELETE
    params = Column(Text) # JSON string of parameters: [{"name": "param1", "type": "text"}, ...]
    type = Column(String(50)) # e.g., FORM, URL_PARAM, API_JS, HEADER
    discovered_at = Column(DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return f"<DiscoveredEndpoint(id={self.id}, url='{self.url}', method='{self.method}', type='{self.type}')>"

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    vulnerability_hash = Column(String, unique=True, nullable=False, index=True) # Unique hash for the vulnerability finding
    url = Column(String, nullable=False, index=True)
    method = Column(String(10), default='N/A')
    vulnerability_type = Column(String(100), nullable=False, index=True) # e.g., XSS, SQLi, CSRF
    payload = Column(Text) # The payload that triggered the vulnerability
    criticality = Column(String(20), default='INFO') # e.g., CRITICAL, HIGH, MEDIUM, LOW, INFO
    proof = Column(Text) # Evidence or response snippet proving the vulnerability
    explanation = Column(Text) # Detailed explanation of the vulnerability
    recommendations = Column(Text) # Mitigation steps
    found_at = Column(DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type='{self.vulnerability_type}', url='{self.url}', criticality='{self.criticality}')>"

class HLNStats(Base):
    __tablename__ = 'hln_stats'
    id = Column(Integer, primary_key=True)
    hln_hash = Column(String, unique=True, nullable=False, index=True) # Unique hash for the HLN instance/endpoint
    url = Column(String, nullable=False, index=True) # The endpoint URL associated with this HLN
    successful_patterns_count = Column(Integer, default=0)
    neuron_weights_avg = Column(Float, default=0.0)
    evolution_data = Column(Text) # JSON string of historical data: e.g., "[(iteration, success_rate), ...]"
    last_updated = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    def __repr__(self):
        return f"<HLNStats(id={self.id}, url='{self.url}', patterns={self.successful_patterns_count}, avg_weights={self.neuron_weights_avg})>"
