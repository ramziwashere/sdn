from mininet.topo import Topo

class MyTopo(Topo):
    "Custom topology example with two directly connected switches and a host for each switch."

    def build(self):
        "Create custom topology."

        # Add hosts
        pc1_site_one = self.addHost('PC1', ip='192.168.1.10')
        pc2_site_one = self.addHost('PC2', ip='192.168.1.11')
        pc3_site_two = self.addHost('PC3', ip='192.168.1.12')
        pc4_site_two = self.addHost('PC4', ip='192.168.1.13')
        internet_pc_edge = self.addHost('InternetPC', ip='192.168.1.254')

        # Add servers
        db_server_site_one = self.addHost('DBServer', ip='192.168.1.51')
        web_server_site_one = self.addHost('WebServer', ip='192.168.1.50')

        # Add switches
        server_farm_site_one = self.addSwitch('s1')
        site_one = self.addSwitch('s2')
        site_two = self.addSwitch('s3')
        edge = self.addSwitch('s4')

        # Add links for Server Farm
        self.addLink(db_server_site_one, server_farm_site_one)
        self.addLink(web_server_site_one, server_farm_site_one)

        # Add links for Site One
        self.addLink(pc1_site_one, site_one)
        self.addLink(pc2_site_one, site_one)

        # Add links for Site Two
        self.addLink(pc3_site_two, site_two)
        self.addLink(pc4_site_two, site_two)

        # Add link for Edge
        self.addLink(internet_pc_edge, edge)

        # Add link for Switches
        self.addLink(server_farm_site_one, site_one)
        self.addLink(site_one, edge)
        self.addLink(edge, site_two)


topos = {'mytopo': (lambda: MyTopo())}
