import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
import os

def visualize_network(devices, interactive=False):
    G = nx.Graph()
    for device in devices:
        G.add_node(device['ip'], hostname=device.get('hostname', 'N/A'), state=device.get('state', 'unknown'))
        for port in device.get('open_ports', []):
            G.add_edge(device['ip'], f"{device['ip']}:{port['port']}", state=port.get('state', 'unknown'), name=port.get('name', 'N/A'), product=port.get('product', 'N/A'))

    if interactive:
        nt = Network('600px', '800px', notebook=True, cdn_resources='in_line')
        nt.from_nx(G)

        for node in G.nodes:
            nt.get_node(node)['title'] = f"Hostname: {G.nodes[node].get('hostname', 'N/A')}, State: {G.nodes[node].get('state', 'unknown')}"
            nt.get_node(node)['color'] = 'green' if G.nodes[node]['state'] == 'up' else 'red'

        for edge in G.edges:
            nt.get_edge(edge[0], edge[1])['title'] = f"Port: {G.edges[edge].get('name', 'N/A')}, Product: {G.edges[edge].get('product', 'N/A')}, State: {G.edges[edge].get('state', 'unknown')}"
            nt.get_edge(edge[0], edge[1])['color'] = 'blue' if G.edges[edge].get('state', 'open') == 'open' else 'black'

        nt.show('network.html')
        os.system("start network.html")
    else:
        pos = nx.spring_layout(G, k=0.15, iterations=20)
        plt.figure(figsize=(12, 8))
        nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold", edge_color="gray")
        labels = nx.get_edge_attributes(G, 'name')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
        plt.title("Network Topology")
        plt.show()
