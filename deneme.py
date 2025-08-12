from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
import networkx as nx


class ChainRoutingController(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ChainRoutingController, self).__init__(*args, **kwargs)
        self.topology = nx.Graph()
        self.datapaths = {}
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.mac_to_dpid_port = {}

    # === WHEN SWITCH CONNECTS ===
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info(f"[Switch Connected] DPID={datapath.id}")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug(f"[Flow Added] DPID={datapath.id}, Match={match}, Actions={actions}")

    # === TOPOLOGY UPDATE ===
    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    def topology_update(self, ev):
        self.logger.info("Updating topology...")
        switch_list = get_switch(self, None)
        link_list = get_link(self, None)

        self.topology.clear()

        for sw in switch_list:
            self.topology.add_node(sw.dp.id)
            self.datapaths[sw.dp.id] = sw.dp

        for link in link_list:
            self.topology.add_edge(link.src.dpid, link.dst.dpid,
                                   port=link.src.port_no)

        self.logger.info(f"Current topology: {list(self.topology.edges(data=True))}")

    # === WHEN PACKET ARRIVES ===
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        self.mac_to_dpid_port[src_mac] = (dpid, in_port)

        # === PROCESS ARP ===
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.ip_to_mac[arp_pkt.src_ip] = src_mac
            self.logger.info(f"ARP: {arp_pkt.src_ip} ({src_mac}) → {arp_pkt.dst_ip}")
            return

        # === PROCESS IPv4 ===
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            self.ip_to_mac[src_ip] = src_mac
            self.logger.info(f"IPv4 Packet: {src_ip} → {dst_ip}")

            out_port = ofproto.OFPP_FLOOD  # default

            if dst_ip in self.ip_to_mac:
                dst_mac = self.ip_to_mac[dst_ip]
                if dst_mac in self.mac_to_dpid_port:
                    dst_dpid, _ = self.mac_to_dpid_port[dst_mac]
                    path = self.get_path(dpid, dst_dpid)

                    if path and len(path) > 1:
                        self.logger.info(f"Path found: {path}")
                        self.install_path(path, src_mac, dst_mac)

                        # Get the first hop of the path
                        if dpid in self.topology and path[1] in self.topology[dpid]:
                            out_port = self.topology[dpid][path[1]]['port']
                        else:
                            self.logger.warning(f"No port info: {dpid} → {path[1]}")
                    else:
                        self.logger.warning(f"No valid path: {dpid} → {dst_dpid}")
                else:
                    self.logger.debug(f"No MAC-to-dpid-port info for {dst_mac}, flooding.")
            else:
                self.logger.debug(f"{dst_ip} unknown, flooding.")

            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath, msg.buffer_id, in_port, actions, data)
            datapath.send_msg(out)

    # === FIND PATH ===
    def get_path(self, src, dst):
        try:
            return nx.shortest_path(self.topology, src, dst)
        except nx.NetworkXNoPath:
            return None

    # === INSTALL FLOWS FOR PATH ===
    def install_path(self, path, src_mac, dst_mac):
        if not path or len(path) < 2:
            self.logger.warning(f"Insufficient path: {path}")
            return

        for i in range(len(path) - 1):
            curr = path[i]
            nxt = path[i + 1]
            if nxt not in self.topology[curr]:
                self.logger.warning(f"No link in topology: {curr} → {nxt}")
                continue

            out_port = self.topology[curr][nxt]['port']
            dp = self.datapaths.get(curr)
            if not dp:
                self.logger.warning(f"Datapath not found: {curr}")
                continue

            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 10, match, actions)
            self.logger.info(f"Flow installed: {curr} → {nxt} | OutPort={out_port}")
