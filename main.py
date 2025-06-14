# main.py
import asyncio
import logging
from src.anonymity.ip_rotator import IPRotator
from src.crawler.crawler import Crawler
from src.profiler.tech_detector import TechDetector # Placeholder, will be implemented
from src.attack_surface.analyzer import AttackSurfaceAnalyzer # Placeholder
from src.orchestrator.attack_orchestrator import AttackOrchestrator, CentralMemory # CentralMemory is here for demo
from src.reporting.pdf_generator import PDFGenerator
from src.reporting.dashboard import run_dashboard, save_data # Import save_data
from urllib.parse import urlparse
import json
import os

# Load configuration
try:
    from config import (
        TARGET_URL, MAX_CRAWL_DEPTH, USE_TOR, TOR_SOCKS_PORT, TOR_CONTROL_PORT, TOR_CONTROL_PASSWORD,
        PROXY_LIST_PATH, REPORT_OUTPUT_DIR, REPORT_BRANDING_LOGO,
        HLN_ITERATIONS_PER_ENDPOINT, HLN_NUM_NEURONS, HLN_LEARNING_RATE, HLN_DECAY_RATE,
        HEADLESS_BROWSER_CRAWLING, LOG_LEVEL
    )
except ImportError:
    print("config.py not found or incomplete. Using default values.")
    TARGET_URL = "http://localhost:8000" # Default safe target
    MAX_CRAWL_DEPTH = 2
    USE_TOR = False
    TOR_SOCKS_PORT = 9050
    TOR_CONTROL_PORT = 9051
    TOR_CONTROL_PASSWORD = None
    PROXY_LIST_PATH = None
    REPORT_OUTPUT_DIR = "reports"
    REPORT_BRANDING_LOGO = None
    HLN_ITERATIONS_PER_ENDPOINT = 5
    HLN_NUM_NEURONS = 5
    HLN_LEARNING_RATE = 0.01
    HLN_DECAY_RATE = 0.001
    HEADLESS_BROWSER_CRAWLING = False
    LOG_LEVEL = "INFO"

# Setup logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper()),
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HebbScan_Main")

async def main():
    logger.info(f"Starting HebbScan on target: {TARGET_URL}")

    # 1. Initialize IP Rotator
    ip_rotator = IPRotator(
        proxy_list_path=PROXY_LIST_PATH,
        use_tor=USE_TOR,
        tor_port=TOR_SOCKS_PORT,
        tor_control_port=TOR_CONTROL_PORT,
        tor_password=TOR_CONTROL_PASSWORD
    )
    await ip_rotator.rotate_ip() # Get initial IP

    # 2. Crawl and Map Architecture
    crawler = Crawler(
        base_url=TARGET_URL,
        ip_rotator=ip_rotator,
        max_depth=MAX_CRAWL_DEPTH,
        headless=HEADLESS_BROWSER_CRAWLING
    )
    visited_urls, discovered_endpoints = await crawler.start_crawl()

    architecture_data = {
        'visited_urls': visited_urls,
        'discovered_endpoints': discovered_endpoints
    }
    logger.info(f"Finished crawling. Discovered {len(visited_urls)} URLs and {len(discovered_endpoints)} endpoints.")

    # 3. Target Profiling (Placeholder)
    # tech_detector = TechDetector(TARGET_URL, ip_rotator)
    # target_tech_profile = await tech_detector.detect_technologies()
    # logger.info(f"Detected technologies: {target_tech_profile}")
    target_tech_profile = {"framework": "Unknown", "server": "Unknown"} # Dummy

    # 4. Attack Surface Analysis (Partially done by crawler, further analysis here)
    # analyzer = AttackSurfaceAnalyzer(discovered_endpoints, target_tech_profile)
    # refined_attack_points = analyzer.analyze()
    refined_attack_points = discovered_endpoints # For demo, use raw discovered endpoints

    # 5. Initialize Central Memory for HLN cross-learning
    central_memory = CentralMemory()

    # 6. Attack Orchestration with Hebbian Learning
    orchestrator = AttackOrchestrator(ip_rotator, central_memory)

    # Define vulnerability types to test (expand this list as needed)
    vulnerability_types_to_test = ['XSS', 'SQLi', 'LFI', 'RCE'] # Add more as they are implemented

    # Iterate through discovered endpoints and test for each vulnerability type
    tasks = []
    for endpoint in refined_attack_points:
        for vuln_type in vulnerability_types_to_test:
            tasks.append(orchestrator.test_endpoint(endpoint, vuln_type, HLN_ITERATIONS_PER_ENDPOINT))

    logger.info(f"Starting {len(tasks)} attack tasks...")
    await asyncio.gather(*tasks) # Run all attack tasks concurrently

    scan_results = orchestrator.get_scan_results()
    hln_stats = orchestrator.get_hebbian_network_stats()
    logger.info(f"Scan finished. Found {len(scan_results)} vulnerabilities.")

    # 7. Reporting
    pdf_generator = PDFGenerator(
        output_path=REPORT_OUTPUT_DIR,
        branding_logo=REPORT_BRANDING_LOGO
    )
    await pdf_generator.generate_report(
        target_url=TARGET_URL,
        scan_results=scan_results,
        architecture_data=architecture_data,
        hln_stats=hln_stats,
        output_filename=f"HebbScan_Report_{urlparse(TARGET_URL).netloc}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    # 8. Prepare data for Dashboard and Launch it
    dashboard_data = {
        "target_url": TARGET_URL,
        "visited_urls": visited_urls,
        "discovered_endpoints": discovered_endpoints,
        "scan_results": scan_results,
        "hln_stats": hln_stats,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    # Save data for Streamlit to load
    save_data(dashboard_data) 
    logger.info(f"Scan data saved to {os.path.join(os.getcwd(), 'scan_results.json')}. Launching dashboard...")

    # Note: Streamlit needs to be run as a separate process.
    # You would typically run the main script, and then in a *separate terminal*, run the dashboard.
    # For a fully integrated script, you might use subprocess, but it complicates process management.
    print("\n--------------------------------------------------------------")
    print(f"Scan completed. PDF report generated in '{REPORT_OUTPUT_DIR}'.")
    print(f"To view the interactive dashboard, run in a NEW TERMINAL:")
    print(f"cd {os.path.abspath('.')}")
    print(f"streamlit run src/reporting/dashboard.py")
    print("--------------------------------------------------------------\n")

if __name__ == "__main__":
    asyncio.run(main())
