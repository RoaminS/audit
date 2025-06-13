import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import json
import logging
import os
from urllib.parse import urlparse # Correction: Ajout de l'import manquant
from utils.database import init_db, load_scan_data_from_db, save_scan_data_to_db
from utils import helpers # For hashing if needed

logger = logging.getLogger(__name__)

# --- Configuration Management ---
CONFIG_FILE = "reporting/config.json" # Assure-toi que ce chemin est correct par rapport à où tu lances Streamlit

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON from {CONFIG_FILE}. Returning default config.")
                # Fallback to default if config file is corrupted
                return get_default_config()
    return get_default_config() # Valeurs par défaut si le fichier n'existe pas

def get_default_config():
    return {
        "dashboard_settings": {
            "data_source": "database" # Changed from "data_file" to "data_source"
        },
        "pdf_settings": {
            "output_path": "reports",
            "branding_logo": "assets/hebbscan_logo.png", # Assure-toi que ce chemin est relatif ou absolu
            "default_report_filename": "HebbScan_Report.pdf",
            "architecture_graph_figsize": [12, 10],
            "vulnerability_map_figsize": [10, 6],
            "learning_curves_figsize": [12, 6],
            "graph_layout_k": 0.15,
            "graph_layout_iterations": 20
        },
        "scan_settings": {
            "default_target_url": "http://testphp.vulnweb.com"
        }
    }

def save_config(config_data):
    # Ensure the directory for CONFIG_FILE exists
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

# Load config when the app starts
config = load_config()

# Data loading functions now abstract the source (DB)
def load_scan_data():
    """Loads scan data from the configured data source (currently database)."""
    # For now, we only support database. If 'data_file' was an option,
    # you'd add logic here to choose between file and DB.
    return load_scan_data_from_db()

def save_scan_data(data):
    """Saves scan data to the configured data source (currently database)."""
    # For now, we only support database.
    save_scan_data_to_db(data)

# Import PDFGenerator if you want to trigger PDF generation from dashboard
from reporting.pdf_generator import PDFGenerator

def run_dashboard():
    st.set_page_config(layout="wide", page_title="HebbScan Dashboard")

    st.sidebar.title("HebbScan Navigation")
    
    # --- Configuration Section in Sidebar ---
    st.sidebar.header("Configuration")
    
    with st.sidebar.expander("Dashboard Settings"):
        # The 'data_file' setting is now replaced by 'data_source'.
        # For simplicity, we'll assume it's always 'database' for now.
        # If you want to switch between file and DB, you'd add a dropdown here.
        st.write("Data Source: Database (fixed for now)")


    with st.sidebar.expander("PDF Report Settings"):
        new_output_path = st.text_input("PDF Output Directory", config['pdf_settings']['output_path'])
        if new_output_path != config['pdf_settings']['output_path']:
            config['pdf_settings']['output_path'] = new_output_path
            save_config(config)

        new_branding_logo = st.text_input("Branding Logo Path", config['pdf_settings']['branding_logo'])
        if new_branding_logo != config['pdf_settings']['branding_logo']:
            config['pdf_settings']['branding_logo'] = new_branding_logo
            save_config(config)
            
        new_report_filename = st.text_input("Default Report Filename", config['pdf_settings']['default_report_filename'])
        if new_report_filename != config['pdf_settings']['default_report_filename']:
            config['pdf_settings']['default_report_filename'] = new_report_filename
            save_config(config)

        st.subheader("Graph Settings")
        new_arch_figsize_w = st.number_input("Arch Graph Width", value=config['pdf_settings']['architecture_graph_figsize'][0], min_value=5, max_value=20)
        new_arch_figsize_h = st.number_input("Arch Graph Height", value=config['pdf_settings']['architecture_graph_figsize'][1], min_value=5, max_value=20)
        if (new_arch_figsize_w != config['pdf_settings']['architecture_graph_figsize'][0] or
            new_arch_figsize_h != config['pdf_settings']['architecture_graph_figsize'][1]):
            config['pdf_settings']['architecture_graph_figsize'] = [new_arch_figsize_w, new_arch_figsize_h]
            save_config(config)

        new_vuln_figsize_w = st.number_input("Vuln Map Width", value=config['pdf_settings']['vulnerability_map_figsize'][0], min_value=5, max_value=20)
        new_vuln_figsize_h = st.number_input("Vuln Map Height", value=config['pdf_settings']['vulnerability_map_figsize'][1], min_value=5, max_value=20)
        if (new_vuln_figsize_w != config['pdf_settings']['vulnerability_map_figsize'][0] or
            new_vuln_figsize_h != config['pdf_settings']['vulnerability_map_figsize'][1]):
            config['pdf_settings']['vulnerability_map_figsize'] = [new_vuln_figsize_w, new_vuln_figsize_h]
            save_config(config)
            
        new_hln_figsize_w = st.number_input("HLN Curves Width", value=config['pdf_settings']['learning_curves_figsize'][0], min_value=5, max_value=20)
        new_hln_figsize_h = st.number_input("HLN Curves Height", value=config['pdf_settings']['learning_curves_figsize'][1], min_value=5, max_value=20)
        if (new_hln_figsize_w != config['pdf_settings']['learning_curves_figsize'][0] or
            new_hln_figsize_h != config['pdf_settings']['learning_curves_figsize'][1]):
            config['pdf_settings']['learning_curves_figsize'] = [new_hln_figsize_w, new_hln_figsize_h]
            save_config(config)

        new_graph_k = st.number_input("Graph Layout K", value=config['pdf_settings']['graph_layout_k'], min_value=0.01, max_value=1.0, step=0.01, format="%.2f")
        new_graph_iter = st.number_input("Graph Layout Iterations", value=config['pdf_settings']['graph_layout_iterations'], min_value=1, max_value=100)
        if new_graph_k != config['pdf_settings']['graph_layout_k'] or new_graph_iter != config['pdf_settings']['graph_layout_iterations']:
            config['pdf_settings']['graph_layout_k'] = new_graph_k
            config['pdf_settings']['graph_layout_iterations'] = new_graph_iter
            save_config(config)

    # Add a button to generate PDF report from the dashboard
    st.sidebar.markdown("---")
    st.sidebar.header("Report Generation")
    if st.sidebar.button("Generate PDF Report"):
        with st.spinner("Generating PDF report..."):
            pdf_generator = PDFGenerator(
                output_path=config['pdf_settings']['output_path'],
                branding_logo=config['pdf_settings']['branding_logo']
            )
            try:
                pdf_generator.generate_report(
                    target_url=scan_data['target_url'],
                    scan_results=scan_data['scan_results'],
                    architecture_data={'visited_urls': scan_data['visited_urls'], 'discovered_endpoints': scan_data['discovered_endpoints']},
                    hln_stats=scan_data['hln_stats'],
                    output_filename=config['pdf_settings']['default_report_filename'],
                    graph_params={ # Pass graph parameters
                        "architecture_graph_figsize": tuple(config['pdf_settings']['architecture_graph_figsize']),
                        "vulnerability_map_figsize": tuple(config['pdf_settings']['vulnerability_map_figsize']),
                        "learning_curves_figsize": tuple(config['pdf_settings']['learning_curves_figsize']),
                        "graph_layout_k": config['pdf_settings']['graph_layout_k'],
                        "graph_layout_iterations": config['pdf_settings']['graph_layout_iterations']
                    }
                )
                st.sidebar.success(f"PDF report generated successfully at {os.path.join(config['pdf_settings']['output_path'], config['pdf_settings']['default_report_filename'])}")
            except Exception as e:
                st.sidebar.error(f"Error generating PDF report: {e}")
                logger.error(f"Error during PDF generation: {e}")
    st.sidebar.markdown("---")

    # Load data for demonstration (from DB now)
    scan_data = load_scan_data()
    
    st.sidebar.header("Scan Information")
    st.sidebar.markdown(f"**Target URL:** {scan_data.get('target_url', 'N/A')}")
    st.sidebar.markdown(f"**Discovered URLs:** {len(scan_data.get('visited_urls', []))}")
    st.sidebar.markdown(f"**Discovered Endpoints:** {len(scan_data.get('discovered_endpoints', []))}")
    st.sidebar.markdown(f"**Vulnerabilities Found:** {len(scan_data.get('scan_results', []))}")

    st.title("HebbScan Automated Security Report Dashboard")

    # Tabbed layout
    tab1, tab2, tab3, tab4 = st.tabs(["Executive Summary", "Architecture & Attack Surface", "Vulnerability Findings", "Hebbian Learning Evolution"])

    with tab1:
        st.header("Executive Summary")
        total_vulnerabilities = len(scan_data.get('scan_results', []))
        critical_count = sum(1 for v in scan_data.get('scan_results', []) if v.get('criticality') == 'CRITICAL')
        high_count = sum(1 for v in scan_data.get('scan_results', []) if v.get('criticality') == 'HIGH')
        medium_count = sum(1 for v in scan_data.get('scan_results', []) if v.get('criticality') == 'MEDIUM')
        low_count = sum(1 for v in scan_data.get('scan_results', []) if v.get('criticality') == 'LOW')

        st.markdown(f"""
        This dashboard provides an interactive overview of the security assessment conducted by HebbScan on **{scan_data.get('target_url', 'N/A')}**.
        <br/><br/>
        A total of **{total_vulnerabilities}** potential vulnerabilities were identified:
        -   **Critical:** {critical_count}
        -   **High:** {high_count}
        -   **Medium:** {medium_count}
        -   **Low:** {low_count}
        """, unsafe_allow_html=True)

        if total_vulnerabilities > 0:
            criticality_counts = pd.DataFrame({
                'Criticality': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                'Count': [critical_count, high_count, medium_count, low_count]
            })
            fig = px.pie(criticality_counts, values='Count', names='Criticality', title='Vulnerabilities by Criticality',
                            color_discrete_map={'CRITICAL':'red', 'HIGH':'orange', 'MEDIUM':'yellow', 'LOW':'green'})
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.header("Scanned Architecture & Attack Surface")
        st.markdown("This section visualizes the website architecture discovered by HebbScan and highlights potential attack surface points.")

        G = nx.DiGraph()
        
        # Add visited URLs as nodes
        for url in scan_data.get('visited_urls', []):
            G.add_node(url, type='URL', color='skyblue')
        
        # Add discovered endpoints and their connections
        for ep in scan_data.get('discovered_endpoints', []):
            ep_url = ep['url']
            ep_method = ep['method']
            # Ensure the endpoint URL is a node
            if ep_url not in G:
                G.add_node(ep_url, type='Endpoint', color='lightcoral')
            
            # Add an edge from the base URL (if distinct) to the endpoint
            if scan_data.get('target_url') and ep_url != scan_data['target_url']:
                # Ensure the target_url node exists
                if scan_data['target_url'] not in G:
                    G.add_node(scan_data['target_url'], type='URL', color='skyblue')
                G.add_edge(scan_data['target_url'], ep_url, label=f"Discovered ({ep_method})")

        if G.nodes:
            try:
                import matplotlib.pyplot as plt
                # Use figsize from config for dashboard's matplotlib graph
                fig, ax = plt.subplots(figsize=tuple(config['pdf_settings']['architecture_graph_figsize'])) 
                pos = nx.spring_layout(G, k=config['pdf_settings']['graph_layout_k'], iterations=config['pdf_settings']['graph_layout_iterations'], seed=42)
                
                node_colors = [G.nodes[node]['color'] for node in G.nodes()]
                nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000, alpha=0.9, ax=ax)
                nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, alpha=0.6, ax=ax)
                nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold', ax=ax)
                
                edge_labels = nx.get_edge_attributes(G, 'label')
                nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, ax=ax)

                ax.set_title("Reconstituted Website Architecture")
                ax.axis('off')
                st.pyplot(fig)
                plt.close(fig) # Close the figure to free memory
            except Exception as e:
                st.warning(f"Could not render architecture graph. Ensure matplotlib and networkx are installed. Error: {e}")

        st.subheader("Discovered Endpoints Details")
        if scan_data.get('discovered_endpoints', []):
            df_endpoints = pd.DataFrame(scan_data['discovered_endpoints'])
            st.dataframe(df_endpoints[['url', 'method', 'type', 'params']].set_index('url'))
        else:
            st.info("No specific attack surface endpoints identified.")

    with tab3:
        st.header("Vulnerability Findings")
        st.markdown("Detailed list of detected vulnerabilities, including payload and recommendations.")

        if scan_data.get('scan_results', []):
            df_vulnerabilities = pd.DataFrame(scan_data['scan_results'])
            
            st.subheader("Filter Findings")
            vuln_type_filter = st.multiselect("Filter by Vulnerability Type", df_vulnerabilities['vulnerability_type'].unique())
            criticality_filter = st.multiselect("Filter by Criticality", df_vulnerabilities['criticality'].unique(), default=df_vulnerabilities['criticality'].unique())

            filtered_df = df_vulnerabilities
            if vuln_type_filter:
                filtered_df = filtered_df[filtered_df['vulnerability_type'].isin(vuln_type_filter)]
            if criticality_filter:
                filtered_df = filtered_df[filtered_df['criticality'].isin(criticality_filter)]
            
            st.dataframe(filtered_df[['url', 'vulnerability_type', 'criticality', 'payload']].set_index('url'), use_container_width=True)

            st.subheader("Details")
            if not filtered_df.empty:
                selected_vuln_url = st.selectbox("Select a vulnerability by URL for details:", filtered_df['url'].unique())
                if selected_vuln_url:
                    selected_vuln = filtered_df[filtered_df['url'] == selected_vuln_url].iloc[0]
                    st.json(selected_vuln.to_dict()) # Display all details as JSON
            else:
                st.info("No vulnerabilities match the current filters.")

        else:
            st.info("No vulnerabilities detected in the scan data.")

    with tab4:
        st.header("Hebbian Learning Evolution")
        st.markdown("This section showcases the adaptive learning process of the Hebbian Networks.")
        
        if scan_data.get('hln_stats', {}):
            hln_df = pd.DataFrame.from_dict(scan_data['hln_stats'], orient='index')
            hln_df['endpoint_url'] = hln_df['url']
            
            st.subheader("Successful Patterns per Endpoint")
            fig = px.bar(hln_df, x='endpoint_url', y='successful_patterns_count', 
                            title='Number of Successful Patterns per Endpoint',
                            labels={'endpoint_url': 'Endpoint URL', 'successful_patterns_count': 'Successful Patterns'})
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Average Neuron Weights Evolution (Conceptual)")
            fig = px.bar(hln_df, x='endpoint_url', y='neuron_weights_avg', 
                            title='Average Neuron Weights per Endpoint (Proxy for Learning Progression)',
                            labels={'endpoint_url': 'Endpoint URL', 'neuron_weights_avg': 'Average Neuron Weight'})
            st.plotly_chart(fig, use_container_width=True)

            st.info("Note: True 'learning curves' would require plotting metrics (e.g., success rate, weight changes) over iterations for each HLN. The current view shows a snapshot of final states.")
        else:
            st.info("No Hebbian Learning Network statistics available.")

# To run the dashboard: `streamlit run reporting/dashboard.py`

# Example of how to populate DATA_FILE for dashboard demo
if __name__ == "__main__":
    # Initialize the database (create tables if they don't exist)
    init_db()

    # Create dummy scan data as per the previous example
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
            {"url": "http://testphp.vulnweb.com/login.php", "method": "POST", "params": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}], "type": "FORM", "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/login.php", "method": "POST"})},
            {"url": "http://testphp.vulnweb.com/search.php", "method": "GET", "params": [{"name": "query", "type": "text"}], "type": "FORM", "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/search.php", "method": "GET"})},
            {"url": "http://testphp.vulnweb.com/listproducts.php", "method": "GET", "params": [{"name": "cat", "type": "text"}], "type": "URL_PARAM", "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/listproducts.php", "method": "GET", "params": [{"name": "cat", "type": "text"}]})},
            {"url": "http://testphp.vulnweb.com/api/v1/users", "method": "GET", "params": [], "type": "API_JS", "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/api/v1/users", "method": "GET"})}
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
                "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/search.php", "vulnerability_type": "XSS", "payload": "<script>alert(document.cookie)</script>"})
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
                "hash": helpers.hash_data({"url": "http://testphp.vulnweb.com/listproducts.php", "vulnerability_type": "SQLi", "payload": "' OR 1=1 --"})
            }
        ],
        "hln_stats": {
            helpers.hash_data({"url": "http://testphp.vulnweb.com/search.php"}): {"url": "http://testphp.vulnweb.com/search.php", "successful_patterns_count": 3, "neuron_weights_avg": 0.75, "evolution_data": [[1, 0.3], [5, 0.5], [10, 0.7]]},
            helpers.hash_data({"url": "http://testphp.vulnweb.com/login.php"}): {"url": "http://testphp.vulnweb.com/login.php", "successful_patterns_count": 1, "neuron_weights_avg": 0.5, "evolution_data": [[1, 0.2], [3, 0.4]]}
        }
    }
    
    # Save the dummy data to the database
    save_scan_data(dummy_scan_data)
    print(f"Dummy scan data saved to database. Run `streamlit run reporting/dashboard.py` to view.")
    run_dashboard() # This will run the dashboard directly if this file is executed.
