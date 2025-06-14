from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
import io
import datetime
import os
import matplotlib.pyplot as plt
import networkx as nx
import logging
import json # Added to load config
from urllib.parse import urlparse # Added for base URL extraction

logger = logging.getLogger(__name__)

# --- Configuration Management (for default values if called directly) ---
CONFIG_FILE = "reporting/config.json"

def load_config_for_pdf_generator():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON from {CONFIG_FILE}. Returning default config.")
                # Fallback to default if config file is corrupted
                return get_default_pdf_config()
    return get_default_pdf_config()

def get_default_pdf_config():
    return { # Default values
        "pdf_settings": {
            "output_path": "reports",
            "branding_logo": "assets/hebbscan_logo.png",
            "default_report_filename": "HebbScan_Report.pdf",
            "architecture_graph_figsize": [12, 10],
            "vulnerability_map_figsize": [10, 6],
            "learning_curves_figsize": [12, 6],
            "graph_layout_k": 0.15,
            "graph_layout_iterations": 20
        }
    }

class PDFGenerator:
    def __init__(self, output_path=None, branding_logo=None):
        # Load config only if paths are not provided (when called directly, not from dashboard)
        if output_path is None or branding_logo is None:
            default_config = load_config_for_pdf_generator()['pdf_settings']
            self.output_path = output_path if output_path is not None else default_config['output_path']
            self.branding_logo = branding_logo if branding_logo is not None else default_config['branding_logo']
        else:
            self.output_path = output_path
            self.branding_logo = branding_logo # Path to a logo image

        os.makedirs(self.output_path, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='H1', fontSize=24, leading=28, alignment=TA_CENTER, spaceAfter=20))
        self.styles.add(ParagraphStyle(name='H2', fontSize=18, leading=22, spaceAfter=14))
        self.styles.add(ParagraphStyle(name='H3', fontSize=14, leading=18, spaceAfter=10))
        self.styles.add(ParagraphStyle(name='Normal', fontSize=10, leading=12, spaceAfter=6))
        self.styles.add(ParagraphStyle(name='Code', fontName='Courier', fontSize=9, leading=10, spaceAfter=4, backColor=colors.lightgrey))
        
        # Store graph parameters initialized in generate_report
        self.graph_params = {} 

    def _generate_architecture_graph(self, visited_urls, discovered_endpoints, target_base_url, filename="architecture_map.png"):
        G = nx.DiGraph()
        nodes = set()
        
        # Add URLs as nodes
        for url in visited_urls:
            G.add_node(url, type='URL')
            nodes.add(url)
        
        # Add discovered endpoints and their connections
        for endpoint in discovered_endpoints:
            ep_url = endpoint['url']
            ep_method = endpoint['method']
            
            # Add endpoint as a node if not already a URL node
            if ep_url not in nodes:
                G.add_node(ep_url, type='Endpoint')
                nodes.add(ep_url)
            
            # For simplicity, connect the base URL to discovered endpoints if they are different
            if target_base_url in G and ep_url in G and ep_url != target_base_url: 
                G.add_edge(target_base_url, ep_url, label=f"Discovered ({ep_method})")


        plt.figure(figsize=self.graph_params.get('architecture_graph_figsize', (12, 10)))
        pos = nx.spring_layout(G, k=self.graph_params.get('graph_layout_k', 0.15), iterations=self.graph_params.get('graph_layout_iterations', 20)) # Positions for nodes
        
        node_colors = []
        for node in G.nodes():
            if G.nodes[node]['type'] == 'URL':
                node_colors.append('skyblue')
            elif G.nodes[node]['type'] == 'Endpoint':
                node_colors.append('lightcoral')
            else:
                node_colors.append('lightgray')

        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000, alpha=0.9)
        nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, alpha=0.6)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')
        
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

        plt.title("Reconstituted Website Architecture")
        plt.axis('off')
        
        filepath = os.path.join(self.output_path, filename)
        plt.savefig(filepath, bbox_inches='tight')
        plt.close() # Close the figure to free memory
        logger.info(f"Generated architecture graph: {filepath}")
        return filepath

    def _generate_vulnerability_map(self, vulnerabilities, filename="vulnerability_map.png"):
        if not vulnerabilities:
            logger.warning("No vulnerabilities to map.")
            return None

        vuln_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

        types = list(vuln_counts.keys())
        counts = list(vuln_counts.values())

        plt.figure(figsize=self.graph_params.get('vulnerability_map_figsize', (10, 6)))
        plt.bar(types, counts, color='lightcoral')
        plt.xlabel("Vulnerability Type")
        plt.ylabel("Number of Findings")
        plt.title("Vulnerabilities by Type")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        filepath = os.path.join(self.output_path, filename)
        plt.savefig(filepath, bbox_inches='tight')
        plt.close() # Close the figure to free memory
        logger.info(f"Generated vulnerability map: {filepath}")
        return filepath
    
    def _generate_learning_curves(self, hln_stats, filename="learning_curves.png"):
        if not hln_stats:
            logger.warning("No HLN stats to plot.")
            return None
        
        plt.figure(figsize=self.graph_params.get('learning_curves_figsize', (12, 6)))
        
        plot_data = []
        bar_data = []

        for ep_hash, stats in hln_stats.items():
            # Ensure 'evolution_data' is a list (it's stored as JSON string in DB)
            evolution_data = json.loads(stats.get('evolution_data', '[]'))
            
            if evolution_data:
                iterations = [item[0] for item in evolution_data]
                success_rates = [item[1] for item in evolution_data]
                plot_data.append({'x': iterations, 'y': success_rates, 'label': f"HLN for {stats['url']}"})
            else:
                # Fallback to bar chart for successful patterns if no evolution data
                bar_data.append({'x': stats['url'][:20] + '...', 'y': stats['successful_patterns_count'], 'label': f"Successful Patterns: {stats['url']}"})

        if plot_data:
            for item in plot_data:
                plt.plot(item['x'], item['y'], label=item['label'])
            plt.xlabel("Iteration")
            plt.ylabel("Success Rate")
            plt.legend()
            plt.grid(True)
        elif bar_data: # Fallback to bar chart if only static data is available
            bar_labels = [item['x'] for item in bar_data]
            bar_counts = [item['y'] for item in bar_data]
            plt.bar(bar_labels, bar_counts)
            plt.xlabel("Endpoint / HLN Instance")
            plt.ylabel("Successful Pattern Count")
            plt.xticks(rotation=45, ha='right')
        else:
            logger.warning("No suitable data found in HLN stats for plotting learning curves.")
            plt.close() # Close empty figure
            return None


        plt.title("Evolution of Hebbian Learning Networks")
        plt.tight_layout()

        filepath = os.path.join(self.output_path, filename)
        plt.savefig(filepath, bbox_inches='tight')
        plt.close() # Close the figure to free memory
        logger.info(f"Generated learning curves: {filepath}")
        return filepath


    def generate_report(self, target_url, scan_results, architecture_data, hln_stats, output_filename="HebbScan_Report.pdf", graph_params=None):
        self.target_base_url = target_url # Store for architecture graph (or pass directly)
        
        # Store graph parameters passed from the dashboard
        if graph_params:
            self.graph_params = graph_params
        else: # Load defaults if called directly without params
            self.graph_params = load_config_for_pdf_generator()['pdf_settings'] 

        filepath = os.path.join(self.output_path, output_filename)
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []

        # Title Page
        story.append(Paragraph("HebbScan Automated Security Assessment Report", self.styles['H1']))
        if self.branding_logo and os.path.exists(self.branding_logo):
            logo = Image(self.branding_logo)
            logo.width = 150
            logo.height = 150
            logo.hAlign = 'CENTER'
            story.append(logo)
            story.append(Spacer(1, 24))
        story.append(Paragraph(f"Target: {target_url}", self.styles['H2']))
        story.append(Paragraph(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 48))
        story.append(Paragraph("Generated by HebbScan - An Intelligent Web Security Pipeline", self.styles['Normal']))
        story.append(PageBreak())

        # Table of Contents (can be auto-generated by ReportLab or manually added)
        story.append(Paragraph("Table of Contents", self.styles['H2']))
        story.append(Paragraph("1. Executive Summary", self.styles['Normal']))
        story.append(Paragraph("2. Scanned Architecture", self.styles['Normal']))
        story.append(Paragraph("3. Attack Surface Analysis", self.styles['Normal'])) # This was implicitly in architecture, now explicit
        story.append(Paragraph("4. Vulnerability Findings", self.styles['Normal']))
        story.append(Paragraph("5. Hebbian Learning Evolution", self.styles['Normal']))
        story.append(PageBreak())

        # 1. Executive Summary
        story.append(Paragraph("1. Executive Summary", self.styles['H2']))
        total_vulnerabilities = len(scan_results)
        critical_count = sum(1 for v in scan_results if v.get('criticality') == 'CRITICAL')
        high_count = sum(1 for v in scan_results if v.get('criticality') == 'HIGH')
        medium_count = sum(1 for v in scan_results if v.get('criticality') == 'MEDIUM')
        low_count = sum(1 for v in scan_results if v.get('criticality') == 'LOW')

        summary_text = f"""
        This report summarizes the findings of an automated security assessment performed by HebbScan on the target website: <b>{target_url}</b>.
        <br/><br/>
        The scan identified a total of <b>{total_vulnerabilities}</b> potential vulnerabilities, categorized as follows:
        <ul>
            <li><b>Critical:</b> {critical_count}</li>
            <li><b>High:</b> {high_count}</li>
            <li><b>Medium:</b> {medium_count}</li>
            <li><b>Low:</b> {low_count}</li>
        </ul>
        HebbScan utilized an adaptive Hebbian Learning Network to dynamically generate and test attack patterns, evolving its strategies based on the target's responses.
        Further details on the discovered architecture, specific vulnerabilities, and the learning process are provided in the following sections.
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(PageBreak())

        # 2. Scanned Architecture
        story.append(Paragraph("2. Scanned Architecture", self.styles['H2']))
        story.append(Paragraph(f"HebbScan successfully crawled and mapped {len(architecture_data['visited_urls'])} unique URLs on the target website.", self.styles['Normal']))
        
        # Base URL extraction from target_url
        parsed_target_url = urlparse(target_url)
        target_base_url = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}"

        arch_graph_path = self._generate_architecture_graph(architecture_data['visited_urls'], architecture_data['discovered_endpoints'], target_base_url)
        if arch_graph_path:
            story.append(Image(arch_graph_path, width=400, height=300)) # Adjust size as needed
            story.append(Paragraph("<i>Figure 1: Reconstituted Website Architecture</i>", self.styles['Normal']))
            story.append(Spacer(1, 12))
        else:
            story.append(Paragraph("<i>No architecture graph could be generated due to insufficient data.</i>", self.styles['Normal']))
        story.append(PageBreak())

        # 3. Attack Surface Analysis
        story.append(Paragraph("3. Attack Surface Analysis", self.styles['H2']))
        story.append(Paragraph(f"A total of {len(architecture_data['discovered_endpoints'])} potential attack endpoints were identified.", self.styles['Normal']))
        if architecture_data['discovered_endpoints']:
            endpoint_data = [['URL', 'Method', 'Type', 'Parameters']]
            for ep in architecture_data['discovered_endpoints']:
                # Ensure parameters are in a readable format, e.g., JSON string or simplified
                params_display = json.dumps(ep.get('params', [])) if ep.get('params') else 'N/A'
                endpoint_data.append([ep.get('url', 'N/A'), ep.get('method', 'N/A'), ep.get('type', 'UNKNOWN'), params_display])
            
            table = Table(endpoint_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#212121')), # Dark background for header
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), # White text for header
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8), # Smaller font for table content
                ('WORDWRAP', (0,0), (-1,-1), 'LTR'), # Ensure text wraps
            ]))
            story.append(table)
        else:
            story.append(Paragraph("<i>No specific attack surface endpoints identified.</i>", self.styles['Normal']))
        story.append(PageBreak())


        # 4. Vulnerability Findings
        story.append(Paragraph("4. Vulnerability Findings", self.styles['H2']))
        if scan_results:
            vuln_map_path = self._generate_vulnerability_map(scan_results)
            if vuln_map_path:
                story.append(Image(vuln_map_path, width=400, height=250)) # Adjust size
                story.append(Paragraph("<i>Figure 2: Vulnerabilities by Type</i>", self.styles['Normal']))
                story.append(Spacer(1, 12))
            
            story.append(Paragraph("The following vulnerabilities were identified during the scan:", self.styles['Normal']))
            
            # Group vulnerabilities by criticality for better readability
            criticalities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            for criticality in criticalities:
                vulns_of_criticality = [v for v in scan_results if v.get('criticality') == criticality]
                if vulns_of_criticality:
                    story.append(Paragraph(f"Criticality: {criticality.upper()}", self.styles['H3']))
                    for vuln in vulns_of_criticality:
                        story.append(Paragraph(f"<b>Type:</b> {vuln.get('vulnerability_type', 'N/A')}", self.styles['Normal']))
                        story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", self.styles['Normal']))
                        story.append(Paragraph(f"<b>Method:</b> {vuln.get('method', 'N/A')}", self.styles['Normal']))
                        if vuln.get('payload'):
                            story.append(Paragraph(f"<b>Payload:</b>", self.styles['Normal']))
                            story.append(Paragraph(vuln['payload'], self.styles['Code']))
                        story.append(Paragraph(f"<b>Explanation:</b> {vuln.get('explanation', 'N/A')}", self.styles['Normal']))
                        if vuln.get('proof'):
                            story.append(Paragraph(f"<b>Proof:</b>", self.styles['Normal']))
                            story.append(Paragraph(vuln['proof'], self.styles['Code']))
                        story.append(Paragraph(f"<b>Recommendations:</b> {vuln.get('recommendations', 'N/A')}", self.styles['Normal']))
                        story.append(Spacer(1, 12))
        else:
            story.append(Paragraph("<i>No vulnerabilities were detected in the scan.</i>", self.styles['Normal']))
        story.append(PageBreak())

        # 5. Hebbian Learning Evolution
        story.append(Paragraph("5. Hebbian Learning Evolution", self.styles['H2']))
        if hln_stats:
            story.append(Paragraph("The Hebbian Learning Network (HLN) adaptively generated and refined attack patterns. Here's a summary of its evolution:", self.styles['Normal']))
            
            learning_curves_path = self._generate_learning_curves(hln_stats)
            if learning_curves_path:
                story.append(Image(learning_curves_path, width=500, height=250)) # Adjust size
                story.append(Paragraph("<i>Figure 3: HLN Evolution (Successful Patterns / Success Rate Over Iterations)</i>", self.styles['Normal']))
                story.append(Spacer(1, 12))

            story.append(Paragraph("Key statistics for each HLN instance:", self.styles['Normal']))
            hln_table_data = [['Endpoint URL', 'Successful Patterns', 'Avg. Neuron Weights', 'Evolution Data']]
            for hln_hash, stats in hln_stats.items():
                # Display evolution_data as a simplified string or indicate presence
                evolution_summary = "Available" if json.loads(stats.get('evolution_data', '[]')) else "N/A"
                hln_table_data.append([
                    stats.get('url', 'N/A'),
                    str(stats.get('successful_patterns_count', 0)),
                    f"{stats.get('neuron_weights_avg', 0.0):.2f}",
                    evolution_summary
                ])
            
            hln_table = Table(hln_table_data, colWidths=[200, 100, 100, 80]) # Adjust colWidths as needed
            hln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#212121')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.lightgrey),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
            ]))
            story.append(hln_table)
            story.append(Spacer(1, 12))
            story.append(Paragraph("<i>Note: 'Evolution Data' indicates if time-series data for learning progression is available.</i>", self.styles['Normal']))

        else:
            story.append(Paragraph("<i>No Hebbian Learning Network statistics available for this scan.</i>", self.styles['Normal']))

        # Build the PDF
        doc.build(story)
        logger.info(f"PDF report generated at: {filepath}")
        return filepath

# Example usage for standalone PDF generation
if __name__ == "__main__":
    # Configure logging for standalone run
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Load dummy data for standalone test (should be consistent with database schema)
    # Note: When run via dashboard, data comes from DB. For standalone test, you can mock it.
    # If you want to load from DB for standalone test, uncomment the database imports and load function.
    from utils.database import init_db, load_scan_data_from_db
    from utils.helpers import hash_data

    init_db() # Ensure DB is initialized for loading

    # Populate dummy data and save to DB
    dummy_scan_data = {
        "target_url": "http://testphp.vulnweb.com",
        "visited_urls": [
            "http://testphp.vulnweb.com/",
            "http://testphp.vulnweb.com/login.php",
            "http://testphp.vulnweb.com/search.php",
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "http://testphp.vulnweb.com/artists.php",
            "http://testphp.vulnweb.com/signup.php"
        ],
        "discovered_endpoints": [
            {"url": "http://testphp.vulnweb.com/login.php", "method": "POST", "params": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}], "type": "FORM", "hash": hash_data({"url": "http://testphp.vulnweb.com/login.php", "method": "POST"})},
            {"url": "http://testphp.vulnweb.com/search.php", "method": "GET", "params": [{"name": "query", "type": "text"}], "type": "FORM", "hash": hash_data({"url": "http://testphp.vulnweb.com/search.php", "method": "GET"})},
            {"url": "http://testphp.vulnweb.com/listproducts.php", "method": "GET", "params": [{"name": "cat", "type": "text"}], "type": "URL_PARAM", "hash": hash_data({"url": "http://testphp.vulnweb.com/listproducts.php", "method": "GET", "params": [{"name": "cat", "type": "text"}]})},
            {"url": "http://testphp.vulnweb.com/api/v1/users", "method": "GET", "params": [], "type": "API_JS", "hash": hash_data({"url": "http://testphp.vulnweb.com/api/v1/users", "method": "GET"})}
        ],
        "scan_results": [
            {
                "url": "http://testphp.vulnweb.com/search.php",
                "method": "GET",
                "vulnerability_type": "XSS",
                "payload": "<script>alert(document.cookie)</script>",
                "criticality": "HIGH",
                "proof": "Payload reflected without encoding.",
                "explanation": "Cross-Site Scripting vulnerability.",
                "recommendations": "Encode output.",
                "hash": hash_data({"url": "http://testphp.vulnweb.com/search.php", "vulnerability_type": "XSS", "payload": "<script>alert(document.cookie)</script>"})
            },
            {
                "url": "http://testphp.vulnweb.com/listproducts.php",
                "method": "GET",
                "vulnerability_type": "SQLi",
                "payload": "' OR 1=1 --",
                "criticality": "CRITICAL",
                "proof": "SQL error message detected.",
                "explanation": "SQL Injection vulnerability.",
                "recommendations": "Use prepared statements.",
                "hash": hash_data({"url": "http://testphp.vulnweb.com/listproducts.php", "vulnerability_type": "SQLi", "payload": "' OR 1=1 --"})
            }
        ],
        "hln_stats": {
            hash_data({"url": "http://testphp.vulnweb.com/search.php"}): {"url": "http://testphp.vulnweb.com/search.php", "successful_patterns_count": 3, "neuron_weights_avg": 0.75, "evolution_data": [[1, 0.3], [5, 0.5], [10, 0.7]]},
            hash_data({"url": "http://testphp.vulnweb.com/login.php"}): {"url": "http://testphp.vulnweb.com/login.php", "successful_patterns_count": 1, "neuron_weights_avg": 0.5, "evolution_data": [[1, 0.2], [3, 0.4]]}
        }
    }
    
    # Save the dummy data to the database for the PDF generator to load
    # This ensures consistency if you run PDF generator standalone
    from utils.database import save_scan_data_to_db # Import here if not already at top
    save_scan_data_to_db(dummy_scan_data)

    # Load data from the database to ensure it's retrieved correctly for PDF generation
    loaded_scan_data = load_scan_data_from_db()

    pdf_gen = PDFGenerator(
        output_path=load_config_for_pdf_generator()['pdf_settings']['output_path'],
        branding_logo=load_config_for_pdf_generator()['pdf_settings']['branding_logo']
    )
    
    # Pass the loaded data to the generate_report method
    pdf_gen.generate_report(
        target_url=loaded_scan_data.get('target_url', 'N/A'),
        scan_results=loaded_scan_data.get('scan_results', []),
        architecture_data={'visited_urls': loaded_scan_data.get('visited_urls', []), 'discovered_endpoints': loaded_scan_data.get('discovered_endpoints', [])},
        hln_stats=loaded_scan_data.get('hln_stats', {}),
        output_filename=load_config_for_pdf_generator()['pdf_settings']['default_report_filename'],
        graph_params=load_config_for_pdf_generator()['pdf_settings'] # Pass all graph params
    )
    print(f"Standalone PDF report generated: {os.path.join(pdf_gen.output_path, load_config_for_pdf_generator()['pdf_settings']['default_report_filename'])}")
