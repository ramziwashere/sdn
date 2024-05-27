from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {
            '192.168.1.10': 1,  # PC1
            '192.168.1.11': 2,  # PC2
            '192.168.1.12': 3,  # PC3
            '192.168.1.13': 4,  # PC4
            '192.168.1.50': 5,  # WEB_SERVER
            '192.168.1.51': 6,  # DB_SERVER
            '192.168.1.254': 7  # INTERNET_PC
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.add_default_flows(datapath)

    def add_default_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Rule: Web server has full access to DB server
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src='192.168.1.50',
                                ipv4_dst='192.168.1.51')
        actions = [parser.OFPActionOutput(self.ip_to_port['192.168.1.51'])]
        self.add_flow(datapath, 10, match, actions)

        # Rule: Full access from site 1 and site 2 PCs to Web Server
        for src_ip in ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13']:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src_ip,
                                    ipv4_dst='192.168.1.50')
            actions = [parser.OFPActionOutput(self.ip_to_port['192.168.1.50'])]
            self.add_flow(datapath, 10, match, actions)

        # Rule: Block access from site 1 and site 2 PCs to DB server
        for src_ip in ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13']:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src_ip,
                                    ipv4_dst='192.168.1.51')
            actions = []  # No actions -> Drop the packet
            self.add_flow(datapath, 10, match, actions)

        # Rule: Internet PC can only access Web Server for HTTP (port 80)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src='192.168.1.254',
                                ipv4_dst='192.168.1.50',
                                ip_proto=6,  # TCP
                                tcp_dst=80)
        actions = [parser.OFPActionOutput(self.ip_to_port['192.168.1.50'])]
        self.add_flow(datapath, 10, match, actions)

        # Rule: Block all other traffic from Internet PC
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src='192.168.1.254')
        actions = []  # No actions -> Drop the packet
        self.add_flow(datapath, 10, match, actions)

        # Allow ARP packets
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Install a flow to avoid packet_in next time
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
