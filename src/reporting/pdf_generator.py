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

logger = logging.getLogger(__name__)

class PDFGenerator:
    def __init__(self, output_path="reports", branding_logo=None):
        self.output_path = output_path
        os.makedirs(self.output_path, exist_ok=True)
        self.branding_logo = branding_logo # Path to a logo image
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='H1', fontSize=24, leading=28, alignment=TA_CENTER, spaceAfter=20))
        self.styles.add(ParagraphStyle(name='H2', fontSize=18, leading=22, spaceAfter=14))
        self.styles.add(ParagraphStyle(name='H3', fontSize=14, leading=18, spaceAfter=10))
        self.styles.add(ParagraphStyle(name='Normal', fontSize=10, leading=12, spaceAfter=6))
        self.styles.add(ParagraphStyle(name='Code', fontName='Courier', fontSize=9, leading=10, spaceAfter=4, backColor=colors.lightgrey))

    def _generate_architecture_graph(self, visited_urls, discovered_endpoints, filename="architecture_map.png"):
        G = nx.DiGraph()
        nodes = set()
        edges = set()

        # Add URLs as nodes
        for url in visited_urls:
            G.add_node(url, type='URL')
            nodes.add(url)
        
        # Add endpoints and their connections
        for endpoint in discovered_endpoints:
            ep_url = endpoint['url']
            ep_method = endpoint['method']
            
            # Add endpoint as a node if not already a URL node
            if ep_url not in nodes:
                G.add_node(ep_url, type='Endpoint')
                nodes.add(ep_url)
            
            # For simplicity, connect the base URL to discovered endpoints if they are different
            # More complex logic: connect forms/APIs to the page they were found on
            if ep_url != self.target_base_url: # Assume target_base_url is passed or stored
                 G.add_edge(self.target_base_url, ep_url, label=f"Discovered ({ep_method})")


        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(G, k=0.15, iterations=20) # Positions for nodes
        
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
        plt.close()
        logger.info(f"Generated architecture graph: {filepath}")
        return filepath

    def _generate_vulnerability_map(self, vulnerabilities, filename="vulnerability_map.png"):
        # This is a very simplified example. A real vulnerability map might show
        # vulnerabilities overlaid on the architecture, or a dependency graph of impact.
        # For this demo, a simple bar chart of vulnerabilities by type/criticality.

        if not vulnerabilities:
            logger.warning("No vulnerabilities to map.")
            return None

        vuln_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

        types = list(vuln_counts.keys())
        counts = list(vuln_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(types, counts, color='lightcoral')
        plt.xlabel("Vulnerability Type")
        plt.ylabel("Number of Findings")
        plt.title("Vulnerabilities by Type")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        filepath = os.path.join(self.output_path, filename)
        plt.savefig(filepath, bbox_inches='tight')
        plt.close()
        logger.info(f"Generated vulnerability map: {filepath}")
        return filepath
    
    def _generate_learning_curves(self, hln_stats, filename="learning_curves.png"):
        if not hln_stats:
            logger.warning("No HLN stats to plot.")
            return None
        
        plt.figure(figsize=(12, 6))
        
        for ep_hash, stats in hln_stats.items():
            # For a real learning curve, we'd need historical data (e.g., success rate over time/iterations)
            # This example just plots a static point, but illustrates the idea.
            # Assume 'evolution_data' contains [(iteration, success_rate)]
            if 'evolution_data' in stats and stats['evolution_data']:
                iterations = [item[0] for item in stats['evolution_data']]
                success_rates = [item[1] for item in stats['evolution_data']]
                plt.plot(iterations, success_rates, label=f"HLN for {stats['url']}")
            else: # Placeholder: if no historical data, just show current success count
                plt.bar(stats['url'][:20] + '...', stats['successful_patterns_count'], label=f"Successful Patterns: {stats['url']}")

        plt.xlabel("Iteration / Endpoint")
        plt.ylabel("Success Rate / Pattern Count")
        plt.title("Evolution of Hebbian Learning Networks")
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        filepath = os.path.join(self.output_path, filename)
        plt.savefig(filepath, bbox_inches='tight')
        plt.close()
        logger.info(f"Generated learning curves: {filepath}")
        return filepath


    def generate_report(self, target_url, scan_results, architecture_data, hln_stats, output_filename="HebbScan_Report.pdf"):
        self.target_base_url = target_url # Store for architecture graph
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
        story.append(Paragraph("3. Attack Surface Analysis", self.styles['Normal']))
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
        story.append(Paragraph(f"HebbScan successfully crawled and mapped {len(architecture_data['visited_urls'])} unique URLs and identified {len(architecture_data['discovered_endpoints'])} potential attack endpoints on the target website.", self.styles['Normal']))
        
        arch_graph_path = self._generate_architecture_graph(architecture_data['visited_urls'], architecture_data['discovered_endpoints'])
        if arch_graph_path:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Reconstituted Website Architecture Map:", self.styles['Normal']))
            img = Image(arch_graph_path)
            img.drawWidth = A4[0] - 2 * doc.leftMargin
            img.drawHeight = img.drawWidth * (img.height / img.width) # Maintain aspect ratio
            story.append(img)
            story.append(Spacer(1, 24))
        story.append(PageBreak())

        # 3. Attack Surface Analysis
        story.append(Paragraph("3. Attack Surface Analysis", self.styles['H2']))
        story.append(Paragraph("The following table summarizes the key attack surface elements identified during the reconnaissance phase:", self.styles['Normal']))
        
        if architecture_data['discovered_endpoints']:
            data = [['URL', 'Method', 'Type', 'Parameters (Example)']]
            for ep in architecture_data['discovered_endpoints']:
                params_str = ", ".join([f"{p['name']}:{p['type']}" for p in ep['params']])
                data.append([ep['url'], ep['method'], ep['type'], params_str])
            
            table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ])
            
            # Auto-calculate column widths. Need to be careful with long URLs.
            col_widths = [doc.width * 0.35, doc.width * 0.1, doc.width * 0.15, doc.width * 0.4]
            t = Table(data, colWidths=col_widths)
            t.setStyle(table_style)
            story.append(t)
        else:
            story.append(Paragraph("No specific attack surface endpoints identified.", self.styles['Normal']))
        
        story.append(PageBreak())

        # 4. Vulnerability Findings
        story.append(Paragraph("4. Vulnerability Findings", self.styles['H2']))
        if scan_results:
            vuln_map_path = self._generate_vulnerability_map(scan_results)
            if vuln_map_path:
                story.append(Spacer(1, 12))
                story.append(Paragraph("Overview of Detected Vulnerabilities by Type:", self.styles['Normal']))
                img = Image(vuln_map_path)
                img.drawWidth = A4[0] - 2 * doc.leftMargin
                img.drawHeight = img.drawWidth * (img.height / img.width)
                story.append(img)
                story.append(Spacer(1, 24))

            for i, vuln in enumerate(scan_results):
                story.append(Paragraph(f"4.{i+1}. {vuln.get('vulnerability_type')} - {vuln.get('criticality')} Severity", self.styles['H3']))
                story.append(Paragraph(f"<b>URL:</b> {vuln.get('url')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Method:</b> {vuln.get('method')}", self.styles['Normal']))
                story.append(Paragraph("<b>Payload (Proof of Concept):</b>", self.styles['Normal']))
                story.append(Paragraph(f"{vuln.get('payload')}", self.styles['Code']))
                story.append(Paragraph("<b>Explanation:</b>", self.styles['Normal']))
                story.append(Paragraph(f"{vuln.get('explanation')}", self.styles['Normal']))
                story.append(Paragraph("<b>Proof:</b>", self.styles['Normal']))
                story.append(Paragraph(f"{vuln.get('proof')}", self.styles['Normal']))
                story.append(Paragraph("<b>Recommendations:</b>", self.styles['Normal']))
                story.append(Paragraph(f"{vuln.get('recommendations')}", self.styles['Normal']))
                story.append(Spacer(1, 12))
                if i < len(scan_results) - 1:
                    story.append(Spacer(1, 6)) # Small space between findings
        else:
            story.append(Paragraph("No vulnerabilities were detected during this scan.", self.styles['Normal']))
        story.append(PageBreak())

        # 5. Hebbian Learning Evolution
        story.append(Paragraph("5. Hebbian Learning Evolution", self.styles['H2']))
        story.append(Paragraph("The Hebbian Learning Networks continuously adapted their attack patterns throughout the scan. The following charts illustrate their evolution:", self.styles['Normal']))
        
        hln_curve_path = self._generate_learning_curves(hln_stats)
        if hln_curve_path:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Evolution of Hebbian Learning Networks (Sample):", self.styles['Normal']))
            img = Image(hln_curve_path)
            img.drawWidth = A4[0] - 2 * doc.leftMargin
            img.drawHeight = img.drawWidth * (img.height / img.width)
            story.append(img)
            story.append(Spacer(1, 24))
        else:
            story.append(Paragraph("No Hebbian learning evolution data available for visualization.", self.styles['Normal']))

        story.append(PageBreak())

        # End of Report
        story.append(Paragraph("--- End of Report ---", self.styles['Normal']))

        try:
            doc.build(story)
            logger.info(f"PDF report generated successfully at: {filepath}")
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")

# Example Usage (for testing)
if __name__ == "__main__":
    logger.setLevel(logging.INFO)
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    # Dummy Data for Report Generation
    dummy_scan_results = [
        {
            'url': 'http://testphp.vulnweb.com/search.php?query=test',
            'method': 'GET',
            'vulnerability_type': 'XSS',
            'payload': '<script>alert(document.cookie)</script>',
            'criticality': 'HIGH',
            'proof': "The payload was reflected in the HTML response without proper encoding, executing JavaScript in the browser.",
            'explanation': "The web application is vulnerable to Cross-Site Scripting (XSS), allowing attackers to inject malicious scripts into web pages viewed by other users.",
            'recommendations': "Implement proper input validation and output encoding (e.g., HTML entity encoding) for all user-supplied data before rendering it in the browser."
        },
        {
            'url': 'http://testphp.vulnweb.com/listproducts.php?cat=1',
            'method': 'GET',
            'vulnerability_type': 'SQLi',
            'payload': "' OR 1=1 --",
            'criticality': 'CRITICAL',
            'proof': "The page displayed a database error message: 'You have an error in your SQL syntax...' after injecting the payload, indicating direct database interaction.",
            'explanation': "The application is vulnerable to SQL Injection, enabling attackers to execute arbitrary SQL queries, potentially leading to data exfiltration or manipulation.",
            'recommendations': "Use parameterized queries (prepared statements) or Object-Relational Mappers (ORMs) to prevent SQL injection. Avoid concatenating user input directly into SQL queries."
        },
        {
            'url': 'http://testphp.vulnweb.com/login.php',
            'method': 'POST',
            'vulnerability_type': 'Auth Bypass',
            'payload': "username=' OR '1'='1'--&password=any",
            'criticality': 'HIGH',
            'proof': "Successfully logged in as administrator using the crafted payload, bypassing authentication mechanisms.",
            'explanation': "The authentication logic is flawed, allowing unauthorized access by manipulating login credentials.",
            'recommendations': "Strengthen authentication mechanisms. Implement robust password hashing, multi-factor authentication, and secure session management. Validate and sanitize all login inputs."
        }
    ]

    dummy_architecture_data = {
        'visited_urls': [
            'http://testphp.vulnweb.com/',
            'http://testphp.vulnweb.com/login.php',
            'http://testphp.vulnweb.com/search.php',
            'http://testphp.vulnweb.com/listproducts.php?cat=1',
            'http://testphp.vulnweb.com/artists.php',
            'http://testphp.vulnweb.com/signup.php'
        ],
        'discovered_endpoints': [
            {'url': 'http://testphp.vulnweb.com/login.php', 'method': 'POST', 'params': [{'name': 'username', 'type': 'text'}, {'name': 'password', 'type': 'password'}], 'type': 'FORM'},
            {'url': 'http://testphp.vulnweb.com/search.php', 'method': 'GET', 'params': [{'name': 'query', 'type': 'text'}], 'type': 'FORM'},
            {'url': 'http://testphp.vulnweb.com/listproducts.php', 'method': 'GET', 'params': [{'name': 'cat', 'type': 'text'}], 'type': 'URL_PARAM'},
        ]
    }

    dummy_hln_stats = {
        'endpoint_hash_1': {'url': 'http://testphp.vulnweb.com/search.php', 'successful_patterns_count': 3, 'neuron_weights_avg': 0.75, 'evolution_data': [(1, 0.1), (2, 0.3), (3, 0.6), (4, 0.7), (5, 0.8)]},
        'endpoint_hash_2': {'url': 'http://testphp.vulnweb.com/login.php', 'successful_patterns_count': 1, 'neuron_weights_avg': 0.5, 'evolution_data': [(1, 0.05), (2, 0.1), (3, 0.1), (4, 0.2), (5, 0.5)]},
    }

    generator = PDFGenerator(branding_logo="path/to/your/logo.png") # Replace with a real path if you have one
    # If logo.png doesn't exist, it will simply be skipped.
    
    # Create a dummy logo file for testing
    try:
        from PIL import Image as PILImage
        img = PILImage.new('RGB', (60, 30), color = 'red')
        img.save("path/to/your/logo.png")
        print("Dummy logo created at path/to/your/logo.png")
    except ImportError:
        print("Pillow not installed. Cannot create dummy logo. Install with 'pip install Pillow'")

    asyncio.run(generator.generate_report(
        target_url="http://testphp.vulnweb.com",
        scan_results=dummy_scan_results,
        architecture_data=dummy_architecture_data,
        hln_stats=dummy_hln_stats,
        output_filename="HebbScan_Demo_Report.pdf"
    ))
