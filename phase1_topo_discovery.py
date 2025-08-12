from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import ethernet, packet
from ryu.lib.packet import ether_types
import networkx as nx
import time


class LLDPPathController(app_manager.RyuApp):
    # Ryu expects a *list* named OFP_VERSIONS
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LLDPPathController, self).__init__(*args, **kwargs)
        # Directed graph holds edges with 'port' attribute
        self.topology = nx.DiGraph()
        self.datapaths = {}               # dpid -> Datapath
        self.logged_links = set()         # to avoid duplicate link logs
        self.link_last_seen = {}          # (u,v) -> timestamp (LLDP heartbeat prep)

        # Tunables (can move to a config later)
        self.lldp_stale_sec = 10.0        # heartbeat window (will be used later)

        self.logger.info("[BOOT] Controller initialized (Phase 1: topology discovery).")

    # ---------- Helpers ----------
    def now(self) -> float:
        return time.time()

    def update_topology(self):
        """Rebuild the graph from Ryu's topology API."""
        self.topology.clear()

        switches = get_switch(self, None)
        links    = get_link(self, None)

        for sw in switches:
            dpid = sw.dp.id
            self.topology.add_node(dpid)
            # keep latest datapath object
            self.datapaths[dpid] = sw.dp

        for lk in links:
            # Add bidirectional edges with port attributes
            self.topology.add_edge(lk.src.dpid, lk.dst.dpid, port=lk.src.port_no)
            self.topology.add_edge(lk.dst.dpid, lk.src.dpid, port=lk.dst.port_no)
            # record heartbeat time for both directions
            self.link_last_seen[(lk.src.dpid, lk.dst.dpid)] = self.now()
            self.link_last_seen[(lk.dst.dpid, lk.src.dpid)] = self.now()

    def print_topology(self, note=""):
        """Pretty-print current topology to logs."""
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

    # ---------- Switch features: add table-miss ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)

        self.datapaths[dp.id] = dp
        self.logger.info(f"[FEATURES] Table-miss installed on DPID={dp.id}")

        # Optional: proactively allow LLDP to flow inside Ryu's switches app.
        # (No explicit rule needed usually; ryu.topology handles LLDP frames.)

    # ---------- Switch join ----------
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        self.datapaths[dpid] = ev.switch.dp
        self.logger.info(f"[SWITCH] Enter: DPID={dpid}")
        self.update_topology()
        self.print_topology("After switch enter")

    # ---------- Link add/remove ----------
    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        key = (src.dpid, src.port_no, dst.dpid, dst.port_no)

        if key not in self.logged_links:
            self.logged_links.add(key)
            self.logger.info(f"[LINK] Add: {src.dpid}:{src.port_no} -> {dst.dpid}:{dst.port_no}")

        # refresh graph and heartbeat
        self.update_topology()
        self.print_topology("After link add")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        self.logger.warning(f"[LINK] Delete: {src.dpid}:{src.port_no} -X-> {dst.dpid}:{dst.port_no}")

        # Rely on update_topology() to rebuild graph
        self.update_topology()
        self.print_topology("After link delete")

    # ---------- Packet-in (Phase 1: only ignore LLDP, log others) ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP to keep logs clean
        if eth and eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.logger.info(f"[PKT-IN] DPID={dp.id} IN={in_port} eth_type=0x{eth.ethertype:04x} src={eth.src} dst={eth.dst} (Phase 1: no forwarding)")
        # Phase 1 does not forward; we just observe. Forwarding will come in later phases.
