import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
import os
import webbrowser # For safer file opening
import logging # Add logging import if not already there

def visualize_network(devices, interactive=False):
    G = nx.Graph()
    host_nodes = []
    port_nodes_data = {} # Store data for port nodes to style them later

    for device in devices:
        host_ip = device['ip']
        host_nodes.append(host_ip)
        G.add_node(host_ip, 
                   label=host_ip, # Explicitly set label for host node
                   hostname=device.get('hostname', 'N/A'), 
                   state=device.get('state', 'unknown'),
                   os_info=device.get('os', 'N/A'),
                   num_open_ports=len(device.get('open_ports', [])),
                   node_type='host' # Add a type attribute
                  )
        for port_data in device.get('open_ports', []):
            port_number = port_data.get('port', 'N/A')
            port_id = f"{host_ip}:{port_number}" # This will be the ID for port nodes
            
            # Add port as a distinct node
            G.add_node(port_id, 
                       label=str(port_number), # Port nodes will be labeled with port number
                       title=f"Port: {port_number}\nService: {port_data.get('name', 'N/A')}\nProduct: {port_data.get('product', 'N/A')}\nState: {port_data.get('state', 'N/A')}",
                       port_state=port_data.get('state', 'unknown'),
                       node_type='port' # Add a type attribute
                      )
            port_nodes_data[port_id] = {'state': port_data.get('state', 'unknown')}

            # Edge from host to its port
            G.add_edge(host_ip, port_id,
                       # title for edge can be simpler if port node has full info
                       title=f"Connects to Port {port_number}", 
                       port_state=port_data.get('state', 'unknown')
                      ) 

    if interactive:
        height = '750px'
        if not devices or not any(d.get('open_ports') for d in devices): # If no devices or no open ports, smaller canvas
            height = '300px'
        nt = Network(height, '100%', notebook=True, cdn_resources='in_line', heading='Interactive Network Map')
        
        nt.from_nx(G)

        for node in nt.nodes:
            nx_node_attrs = G.nodes[node['id']] # Get original attributes from NetworkX node
            node_type = nx_node_attrs.get('node_type')

            if node_type == 'host':
                title_parts = [
                    f"IP: {node['id']}",
                    f"Hostname: {nx_node_attrs.get('hostname', 'N/A')}",
                    f"Device State: {nx_node_attrs.get('state', 'unknown')}"
                ]
                os_info = nx_node_attrs.get('os_info', 'N/A')
                if os_info and os_info not in ["OS Detection Disabled", "N/A", "Unknown", "OS detection attempted, no match."]:
                    title_parts.append(f"OS: {os_info}")
                node['title'] = "\n".join(title_parts)
                node['color'] = '#33A1C9' if nx_node_attrs.get('state') == 'up' else '#D32F2F' # Softer Green/Red
                node['value'] = 20 + nx_node_attrs.get('num_open_ports', 0) * 3 # Make host nodes more prominent
                node['shape'] = 'box' if nx_node_attrs.get('num_open_ports', 0) > 0 else 'ellipse'
            
            elif node_type == 'port':
                node['title'] = nx_node_attrs.get('title', 'Port Info') # Already set during G.add_node for port
                port_s = nx_node_attrs.get('port_state', 'unknown')
                if port_s == 'open':
                    node['color'] = '#4CAF50' # Green for open ports
                elif port_s == 'open|filtered':
                    node['color'] = '#FF9800' # Orange for open|filtered ports
                else:
                    node['color'] = '#9E9E9E' # Grey for other states
                node['value'] = 5 # Smaller, fixed size for port nodes
                node['font'] = {'size': 10, 'color': 'black'} # Ensure port label is readable

        for edge in nt.edges:
            nx_edge_attrs = G.get_edge_data(edge['from'], edge['to'])
            if nx_edge_attrs:
                edge['title'] = nx_edge_attrs.get('title', 'Connection')
                port_s = nx_edge_attrs.get('port_state', 'unknown') # Use port_state from edge data
                if port_s == 'open':
                    edge['color'] = '#4CAF50' # Match open port node color
                    edge['width'] = 3
                elif port_s == 'open|filtered':
                    edge['color'] = '#FF9800' # Match open|filtered port node color
                    edge['width'] = 2
                else:
                    edge['color'] = '#E0E0E0' # Lighter grey for less prominent edges
                    edge['width'] = 1
        
        # Consolidate options setting
        options_str = """
        var options = {
          "configure": {
            "enabled": true,
            "filter": "physics,nodes,edges",
            "showButton": true
          },
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -2500,
              "centralGravity": 0.15,
              "springLength": 120,
              "springConstant": 0.05,
              "damping": 0.09,
              "avoidOverlap": 0.1
            },
            "minVelocity": 0.75,
            "solver": "barnesHut"
          }
        }
        """
        nt.set_options(options_str)

        output_filename = 'network_map.html'
        html_content = nt.generate_html()
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logging.info(f"Successfully wrote {output_filename} with UTF-8 encoding.")
        except Exception as e:
            logging.error(f"Error writing HTML to {output_filename}: {e}")
            return

        try:
            webbrowser.open(f'file://{os.path.realpath(output_filename)}')
        except Exception as e:
            logging.error(f"Could not open visualization in browser: {e}")

    else: # Matplotlib static graph (simplified to match focus)
        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(G, k=0.2, iterations=25)
        
        host_node_list = [n for n, attr in G.nodes(data=True) if attr.get('node_type') == 'host']
        port_node_list = [n for n, attr in G.nodes(data=True) if attr.get('node_type') == 'port']

        nx.draw_networkx_nodes(G, pos, nodelist=host_node_list, node_color=['#33A1C9' if G.nodes[n].get('state') == 'up' else '#D32F2F' for n in host_node_list], 
                               node_size=[1500 + G.nodes[n].get('num_open_ports',0)*200 for n in host_node_list], node_shape='s')
        nx.draw_networkx_nodes(G, pos, nodelist=port_node_list, node_color=['#4CAF50' if G.nodes[n].get('port_state') == 'open' else ('#FF9800' if G.nodes[n].get('port_state') == 'open|filtered' else '#9E9E9E') for n in port_node_list], 
                               node_size=300, node_shape='o')
        
        nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5, edge_color="gray")
        
        labels = {n: G.nodes[n].get('label', n) for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight="bold")
        
        plt.title("Network Topology (Static)", fontsize=15)
        plt.axis('off')
        plt.show()
