import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import json
import logging
import os

logger = logging.getLogger(__name__)

# Placeholder for data storage. In a real app, this would query a database.
DATA_FILE = "scan_results.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {"visited_urls": [], "discovered_endpoints": [], "scan_results": [], "hln_stats": {}, "target_url": "N/A"}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def run_dashboard():
    st.set_page_config(layout="wide", page_title="HebbScan Dashboard")

    st.sidebar.title("HebbScan Navigation")
    
    # Load data for demonstration
    scan_data = load_data()
    
    st.sidebar.header("Scan Information")
    st.sidebar.markdown(f"**Target URL:** {scan_data['target_url']}")
    st.sidebar.markdown(f"**Discovered URLs:** {len(scan_data['visited_urls'])}")
    st.sidebar.markdown(f"**Discovered Endpoints:** {len(scan_data['discovered_endpoints'])}")
    st.sidebar.markdown(f"**Vulnerabilities Found:** {len(scan_data['scan_results'])}")

    st.title("HebbScan Automated Security Report Dashboard")

    # Tabbed layout
    tab1, tab2, tab3, tab4 = st.tabs(["Executive Summary", "Architecture & Attack Surface", "Vulnerability Findings", "Hebbian Learning Evolution"])

    with tab1:
        st.header("Executive Summary")
        total_vulnerabilities = len(scan_data['scan_results'])
        critical_count = sum(1 for v in scan_data['scan_results'] if v.get('criticality') == 'CRITICAL')
        high_count = sum(1 for v in scan_data['scan_results'] if v.get('criticality') == 'HIGH')
        medium_count = sum(1 for v in scan_data['scan_results'] if v.get('criticality') == 'MEDIUM')
        low_count = sum(1 for v in scan_data['scan_results'] if v.get('criticality') == 'LOW')

        st.markdown(f"""
        This dashboard provides an interactive overview of the security assessment conducted by HebbScan on **{scan_data['target_url']}**.
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
        nodes_data = []
        edges_data = []

        # Add visited URLs as nodes
        for url in scan_data['visited_urls']:
            G.add_node(url, type='URL', color='skyblue')
            nodes_data.append({'id': url, 'label': urlparse(url).path or '/', 'group': 'URL'})
        
        # Add discovered endpoints and their connections
        for ep in scan_data['discovered_endpoints']:
            ep_url = ep['url']
            ep_method = ep['method']
            # Ensure the endpoint URL is a node
            if ep_url not in G:
                G.add_node(ep_url, type='Endpoint', color='lightcoral')
                nodes_data.append({'id': ep_url, 'label': urlparse(ep_url).path, 'group': 'Endpoint'})
            
            # Add an edge from the base URL (if distinct) to the endpoint
            if ep_url != scan_data['target_url']:
                if scan_data['target_url'] in G and ep_url in G:
                    G.add_edge(scan_data['target_url'], ep_url, label=f"Discovered ({ep_method})")
                    edges_data.append({'source': scan_data['target_url'], 'target': ep_url, 'label': f"Discovered ({ep_method})"})

        if G.nodes:
            # Use Pyvis for interactive graph, but requires HTML export.
            # For direct Streamlit, can use networkx + matplotlib/plotly or a custom d3.js component.
            # For simplicity, we'll draw with networkx and matplotlib for now.
            try:
                import matplotlib.pyplot as plt
                fig, ax = plt.subplots(figsize=(15, 12))
                pos = nx.spring_layout(G, k=0.15, iterations=20, seed=42)
                
                node_colors = [G.nodes[node]['color'] for node in G.nodes()]
                nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000, alpha=0.9, ax=ax)
                nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, alpha=0.6, ax=ax)
                nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold', ax=ax)
                
                edge_labels = nx.get_edge_attributes(G, 'label')
                nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, ax=ax)

                ax.set_title("Reconstituted Website Architecture")
                ax.axis('off')
                st.pyplot(fig)
            except Exception as e:
                st.warning(f"Could not render architecture graph. Ensure matplotlib and networkx are installed. Error: {e}")

        st.subheader("Discovered Endpoints Details")
        if scan_data['discovered_endpoints']:
            df_endpoints = pd.DataFrame(scan_data['discovered_endpoints'])
            st.dataframe(df_endpoints.set_index('url'))
        else:
            st.info("No specific attack surface endpoints identified.")

    with tab3:
        st.header("Vulnerability Findings")
        st.markdown("Detailed list of detected vulnerabilities, including payload and recommendations.")

        if scan_data['scan_results']:
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
            selected_vuln_url = st.selectbox("Select a vulnerability by URL for details:", filtered_df['url'].unique())
            if selected_vuln_url:
                selected_vuln = filtered_df[filtered_df['url'] == selected_vuln_url].iloc[0]
                st.json(selected_vuln.to_dict()) # Display all details as JSON

        else:
            st.info("No vulnerabilities detected in the scan data.")

    with tab4:
        st.header("Hebbian Learning Evolution")
        st.markdown("This section showcases the adaptive learning process of the Hebbian Networks.")
        
        if scan_data['hln_stats']:
            hln_df = pd.DataFrame.from_dict(scan_data['hln_stats'], orient='index')
            hln_df['endpoint_url'] = hln_df['url']
            
            st.subheader("Successful Patterns per Endpoint")
            fig = px.bar(hln_df, x='endpoint_url', y='successful_patterns_count', 
                         title='Number of Successful Patterns per Endpoint',
                         labels={'endpoint_url': 'Endpoint URL', 'successful_patterns_count': 'Successful Patterns'})
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Average Neuron Weights Evolution (Conceptual)")
            # This requires actual time-series data for weights, which isn't in current dummy data.
            # For a real implementation, HLN should log weight changes over iterations.
            # Here, we'll plot average of final weights for each HLN.
            fig = px.bar(hln_df, x='endpoint_url', y='neuron_weights_avg', 
                         title='Average Neuron Weights per Endpoint (Proxy for Learning Progression)',
                         labels={'endpoint_url': 'Endpoint URL', 'neuron_weights_avg': 'Average Neuron Weight'})
            st.plotly_chart(fig, use_container_width=True)

            st.info("Note: True 'learning curves' would require plotting metrics (e.g., success rate, weight changes) over iterations for each HLN. The current view shows a snapshot of final states.")
        else:
            st.info("No Hebbian Learning Network statistics available.")

# To run the dashboard: `streamlit run src/reporting/dashboard.py`

# Example of how to populate DATA_FILE for dashboard demo
if __name__ == "__main__":
    # Create a dummy scan_results.json for testing the dashboard
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
            {"url": "http://testphp.vulnweb.com/login.php", "method": "POST", "params": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}], "type": "FORM"},
            {"url": "http://testphp.vulnweb.com/search.php", "method": "GET", "params": [{"name": "query", "type": "text"}], "type": "FORM"},
            {"url": "http://testphp.vulnweb.com/listproducts.php", "method": "GET", "params": [{"name": "cat", "type": "text"}], "type": "URL_PARAM"},
            {"url": "http://testphp.vulnweb.com/api/v1/users", "method": "GET", "params": [], "type": "API_JS"}
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
                "recommendations": "Encode output."
            },
            {
                "url": "http://testphp.vulnweb.com/listproducts.php",
                "method": "GET",
                "vulnerability_type": "SQLi",
                "payload": "' OR 1=1 --",
                "criticality": "CRITICAL",
                "proof": "SQL error message detected.",
                "explanation": "SQL Injection vulnerability.",
                "recommendations": "Use prepared statements."
            }
        ],
        "hln_stats": {
            "endpoint_hash_1": {"url": "http://testphp.vulnweb.com/search.php", "successful_patterns_count": 3, "neuron_weights_avg": 0.75},
            "endpoint_hash_2": {"url": "http://testphp.vulnweb.com/login.php", "successful_patterns_count": 1, "neuron_weights_avg": 0.5}
        }
    }
    save_data(dummy_scan_data)
    print(f"Dummy scan data saved to {DATA_FILE}. Run `streamlit run src/reporting/dashboard.py` to view.")
    run_dashboard() # This will run the dashboard directly if this file is executed.
