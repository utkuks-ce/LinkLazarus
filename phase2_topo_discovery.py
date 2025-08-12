from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
import networkx as nx
import time


class LLDPPathController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LLDPPathController, self).__init__(*args, **kwargs)
        self.topology = nx.DiGraph()
        self.datapaths = {}
        self.logged_links = set()
        self.link_last_seen = {}

        # Learning tables
        self.mac_to_port = {}          # { dpid: { mac: in_port } }
        self.mac_to_loc  = {}          # { mac: (dpid, port) }
        self.ip_to_mac   = {}          # { ip: mac }
        self.host_last_seen = {}       # { mac: timestamp }

        self.lldp_stale_sec = 10.0
        self.logger.info("[BOOT] Controller initialized (Phase 2: learning).")

    # ---------- helpers ----------
    def now(self) -> float:
        return time.time()

    def update_topology(self):
        self.topology.clear()
        switches = get_switch(self, None)
        links = get_link(self, None)

        for sw in switches:
            dpid = sw.dp.id
            self.topology.add_node(dpid)
            self.datapaths[dpid] = sw.dp

        for lk in links:
            self.topology.add_edge(lk.src.dpid, lk.dst.dpid, port=lk.src.port_no)
            self.topology.add_edge(lk.dst.dpid, lk.src.dpid, port=lk.dst.port_no)
            self.link_last_seen[(lk.src.dpid, lk.dst.dpid)] = self.now()
            self.link_last_seen[(lk.dst.dpid, lk.src.dpid)] = self.now()

    def print_topology(self, note=""):
        if note:
            self.logger.info(f"[TOPOLOGY] {note}")
        if self.topology.number_of_nodes() == 0:
            self.logger.info("[TOPOLOGY] (empty)")
            return
        sws = sorted(list(self.topology.nodes()))
        self.logger.info(f"[TOPOLOGY] Switches: {sws}")
        edges = []
        for u, v, data in self.topology.edges(data=True):
            edges.append((u, v, data.get('port')))
        edges.sort()
        for u, v, p in edges:
            self.logger.info(f"[TOPOLOGY] {u} --(port {p})--> {v}")

    def print_hosts(self):
        if not self.mac_to_loc:
            self.logger.info("[HOSTS] (none learned yet)")
            return
        self.logger.info("[HOSTS] Learned endpoints:")
        for mac, (dpid, port) in self.mac_to_loc.items():
            last = self.host_last_seen.get(mac)
            self.logger.info(f"[HOSTS] mac={mac} at DPID={dpid} PORT={port} last_seen={last}")

    def learn_host(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        prev = self.mac_to_port[dpid].get(src_mac)
        self.mac_to_port[dpid][src_mac] = in_port
        self.mac_to_loc[src_mac] = (dpid, in_port)
        self.host_last_seen[src_mac] = self.now()

        if prev != in_port:
            self.logger.info(f"[LEARN] DPID={dpid} mac={src_mac} IN={in_port} (was: {prev})")

    def flood(self, dp, in_port, data, reason="generic"):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        dp.send_msg(out)
        self.logger.info(f"[FLOOD] DPID={dp.id} IN={in_port} reason={reason}")

    # ---------- features / events ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.datapaths[dp.id] = dp
        self.logger.info(f"[FEATURES] Table-miss installed on DPID={dp.id}")

        # (Optional) low-priority ARP flood rule — ileride ekleyebiliriz.

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        self.datapaths[dpid] = ev.switch.dp
        self.logger.info(f"[SWITCH] Enter: DPID={dpid}")
        self.update_topology()
        self.print_topology("After switch enter")
        
    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        key = (src.dpid, src.port_no, dst.dpid, dst.port_no)
        if key not in self.logged_links:
            self.logged_links.add(key)
            self.logger.info(f"[LINK] Add: {src.dpid}:{src.port_no} -> {dst.dpid}:{dst.port_no}")
        self.update_topology()
        self.print_topology("After link add")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        self.logger.warning(f"[LINK] Delete: {src.dpid}:{src.port_no} -X-> {dst.dpid}:{dst.port_no}")
        self.update_topology()
        self.print_topology("After link delete")

    # ---------- packet-in: learning only ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Learn source on every packet
        self.learn_host(dp.id, eth.src, in_port)

        # ARP?
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # Link IP->MAC
            self.ip_to_mac[arp_pkt.src_ip] = eth.src
            self.logger.info(f"[ARP] src_ip={arp_pkt.src_ip} src_mac={eth.src} op={arp_pkt.opcode}")
            # Phase-2: still learning mode → flood to discover peers
            self.flood(dp, in_port, msg.data, reason="arp")
            self.print_hosts()
            return

        # IPv4?
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.logger.info(f"[IP] DPID={dp.id} IN={in_port} src={ipv4_pkt.src}({eth.src}) dst={ipv4_pkt.dst}({eth.dst})")
            # Learning only (no forwarding yet)
            return

        # Others
        self.logger.info(f"[PKT-IN] DPID={dp.id} IN={in_port} eth_type=0x{eth.ethertype:04x} src={eth.src} dst={eth.dst} (learning only)")
