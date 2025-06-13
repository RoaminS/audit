# utils/database.py

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import logging
import os

# Import models from .models
from .models import Base, URL, DiscoveredEndpoint, Vulnerability, HLNStats

logger = logging.getLogger(__name__)

# Database file path (can be configured externally, e.g., via config.json)
DATABASE_FILE = os.environ.get("HEBBSCAN_DB_FILE", "hebbscan_results.db")
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

# Engine for the database
engine = None

def get_db_connection():
    """
    Provides a SQLAlchemy session. This should be used with 'with' statement.
    Example:
    with get_db_connection() as session:
        # Perform database operations
        url = URL(url="http://example.com")
        session.add(url)
        session.commit()
    """
    global engine
    if engine is None:
        try:
            engine = create_engine(DATABASE_URL, echo=False) # Set echo=True for SQL logging
            logger.info(f"Database engine created for {DATABASE_URL}")
        except sqlalchemy.exc.ArgumentError as e:
            logger.error(f"Invalid database URL: {DATABASE_URL}. Error: {e}")
            raise
    
    Session = sessionmaker(bind=engine)
    return Session()

def init_db():
    """
    Initializes the database by creating all defined tables.
    This should be called once at application startup.
    """
    global engine
    if engine is None:
        engine = create_engine(DATABASE_URL, echo=False)
        logger.info(f"Database engine re-created for initialization for {DATABASE_URL}")

    try:
        # Create all tables defined in Base's metadata
        Base.metadata.create_all(engine)
        logger.info(f"Database tables created successfully in {DATABASE_FILE}")
    except SQLAlchemyError as e:
        logger.error(f"Error creating database tables: {e}")
        # Depending on the error, you might want to exit or handle gracefully
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred during database initialization: {e}")
        raise

# Example: How to use these functions to save data from scan_results.json
def save_scan_data_to_db(scan_data):
    """
    Saves the processed scan data (from the JSON structure) into the database.
    This function bridges the JSON file format with the database models.
    """
    logger.info("Saving scan data to database...")
    with get_db_connection() as session:
        try:
            target_url_obj = URL(url=scan_data.get('target_url', 'N/A'),
                                 is_target=True)
            session.add(target_url_obj)
            session.commit() # Commit to get ID for target_url_obj if needed later

            # Visited URLs
            for url_str in scan_data.get('visited_urls', []):
                # Check if URL already exists to prevent duplicates
                existing_url = session.query(URL).filter_by(url=url_str).first()
                if not existing_url:
                    session.add(URL(url=url_str))
            
            # Discovered Endpoints
            for ep_data in scan_data.get('discovered_endpoints', []):
                # Use hash to check for uniqueness, or find by url+method
                ep_hash = ep_data.get('hash', helpers.hash_data(ep_data)) # Assume hash is added by scanner or generate
                existing_ep = session.query(DiscoveredEndpoint).filter_by(endpoint_hash=ep_hash).first()
                if not existing_ep:
                    session.add(DiscoveredEndpoint(
                        endpoint_hash=ep_hash,
                        url=ep_data['url'],
                        method=ep_data.get('method', 'GET'),
                        params=json.dumps(ep_data.get('params', [])), # Store params as JSON string
                        type=ep_data.get('type', 'UNKNOWN')
                    ))
            
            # Scan Results (Vulnerabilities)
            for vuln_data in scan_data.get('scan_results', []):
                vuln_hash = helpers.hash_data({ # Create a hash for uniqueness of vulnerability finding
                    'url': vuln_data.get('url'),
                    'vulnerability_type': vuln_data.get('vulnerability_type'),
                    'payload': vuln_data.get('payload')
                })
                existing_vuln = session.query(Vulnerability).filter_by(vulnerability_hash=vuln_hash).first()
                if not existing_vuln:
                    session.add(Vulnerability(
                        vulnerability_hash=vuln_hash,
                        url=vuln_data['url'],
                        method=vuln_data.get('method', 'N/A'),
                        vulnerability_type=vuln_data['vulnerability_type'],
                        payload=vuln_data.get('payload', ''),
                        criticality=vuln_data.get('criticality', 'INFO'),
                        proof=vuln_data.get('proof', ''),
                        explanation=vuln_data.get('explanation', ''),
                        recommendations=vuln_data.get('recommendations', '')
                    ))

            # HLN Stats
            for hln_hash, hln_data in scan_data.get('hln_stats', {}).items():
                existing_hln = session.query(HLNStats).filter_by(hln_hash=hln_hash).first()
                if not existing_hln:
                    session.add(HLNStats(
                        hln_hash=hln_hash,
                        url=hln_data['url'],
                        successful_patterns_count=hln_data.get('successful_patterns_count', 0),
                        neuron_weights_avg=hln_data.get('neuron_weights_avg', 0.0),
                        evolution_data=json.dumps(hln_data.get('evolution_data', [])) # Store as JSON string
                    ))
                else:
                    # Update existing stats if necessary (e.g., if this is a scan update)
                    existing_hln.successful_patterns_count = hln_data.get('successful_patterns_count', 0)
                    existing_hln.neuron_weights_avg = hln_data.get('neuron_weights_avg', 0.0)
                    existing_hln.evolution_data = json.dumps(hln_data.get('evolution_data', []))

            session.commit()
            logger.info("Scan data saved to database successfully.")
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error during saving scan data: {e}")
        except Exception as e:
            session.rollback()
            logger.error(f"An unexpected error occurred while saving scan data: {e}")

# Example: How to load data from the database for the dashboard/report
def load_scan_data_from_db():
    """
    Loads all relevant scan data from the database and returns it in a format
    similar to the original JSON structure.
    """
    logger.info("Loading scan data from database...")
    scan_data = {
        "target_url": "N/A",
        "visited_urls": [],
        "discovered_endpoints": [],
        "scan_results": [],
        "hln_stats": {}
    }

    with get_db_connection() as session:
        try:
            # Target URL
            target_url_obj = session.query(URL).filter_by(is_target=True).first()
            if target_url_obj:
                scan_data['target_url'] = target_url_obj.url
            
            # Visited URLs
            visited_urls_objs = session.query(URL).all()
            scan_data['visited_urls'] = [url_obj.url for url_obj in visited_urls_objs]

            # Discovered Endpoints
            endpoints_objs = session.query(DiscoveredEndpoint).all()
            scan_data['discovered_endpoints'] = [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "params": json.loads(ep.params) if ep.params else [],
                    "type": ep.type,
                    "hash": ep.endpoint_hash # Include hash for consistency
                } for ep in endpoints_objs
            ]

            # Scan Results
            vulns_objs = session.query(Vulnerability).all()
            scan_data['scan_results'] = [
                {
                    "url": vuln.url,
                    "method": vuln.method,
                    "vulnerability_type": vuln.vulnerability_type,
                    "payload": vuln.payload,
                    "criticality": vuln.criticality,
                    "proof": vuln.proof,
                    "explanation": vuln.explanation,
                    "recommendations": vuln.recommendations,
                    "hash": vuln.vulnerability_hash # Include hash for consistency
                } for vuln in vulns_objs
            ]

            # HLN Stats
            hln_stats_objs = session.query(HLNStats).all()
            for hln_obj in hln_stats_objs:
                scan_data['hln_stats'][hln_obj.hln_hash] = {
                    "url": hln_obj.url,
                    "successful_patterns_count": hln_obj.successful_patterns_count,
                    "neuron_weights_avg": hln_obj.neuron_weights_avg,
                    "evolution_data": json.loads(hln_obj.evolution_data) if hln_obj.evolution_data else [],
                    "hash": hln_obj.hln_hash
                }
            
            logger.info("Scan data loaded from database successfully.")
            return scan_data

        except SQLAlchemyError as e:
            logger.error(f"Database error during loading scan data: {e}")
            return scan_data # Return partial data or empty data on error
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading scan data: {e}")
            return scan_data
