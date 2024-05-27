"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts
        PC1_SITEONE = self.addHost( 'PC1', ip='192.168.1.10')
        PC2_SITEONE = self.addHost( 'PC2', ip='192.168.1.11' )
        PC3_SITETWO = self.addHost( 'PC3', ip='192.168.1.12')
        PC4_SITETWO = self.addHost( 'PC4', ip='192.168.1.13' )
        INTERNET_PC_EDGE= self.addHost( 'Internet PC', ip='192.168.1.254' )
        
        # Add Servers
        DB_SERVER_SITEONE = self.addHost( 'DB Server', ip='192.168.1.51' )
        WEB_SERVER_SITEONE = self.addHost( 'Web Server', ip='192.168.1.50' )

        # Add Switches
        SERVER_FARM_SITEONE = self.addSwitch( 's1' )
        SITEONE = self.addSwitch( 's2' )
        SITETWO = self.addSwitch( 's3' )
        EDGE = self.addSwitch( 's4' )

        # Add links for Server Farm 
        self.addLink( DB_SERVER_SITEONE, SERVER_FARM_SITEONE)
        self.addLink( WEB_SERVER_SITEONE, SERVER_FARM_SITEONE)

        # Add links for Site One
        self.addLink( PC1_SITEONE, SITEONE )
        self.addLink( PC2_SITEONE, SITEONE )

        # Add links for Site Two
        self.addLink( PC3_SITETWO, SITETWO )
        self.addLink( PC4_SITETWO, SITETWO )

        # Add link for Edge
        self.addLink( INTERNET_PC_EDGE, EDGE )

        # Add link for Switches
        self.addLink( SERVER_FARM_SITEONE, SITEONE )
        self.addLink( SITEONE, EDGE )
        self.addLink( EDGE, SITETWO )


topos = { 'mytopo': ( lambda: MyTopo() ) }