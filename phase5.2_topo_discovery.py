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
from ryu.topology import switches as topo_switches  # Ryu’nun hazır LLDPPacket helper’ı
from ryu.lib import hub  # periyodik beacon için



class LLDPPathController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LLDPPathController, self).__init__(*args, **kwargs)
        # Graph + state
        self.topology = nx.DiGraph()
        self.datapaths = {}               # dpid -> Datapath
        self.logged_links = set()
        self.link_last_seen = {}

        # Learning tables
        self.mac_to_port = {}             # { dpid: { mac: in_port } }
        self.mac_to_loc  = {}             # { mac: (dpid, port) }
        self.ip_to_mac   = {}             # { ip: mac }
        self.host_last_seen = {}          # { mac: timestamp }

        self.lldp_stale_sec = 10.0
        self.logger.info("[BOOT] Controller initialized (Phase 4: learning + SPF).")
        self.link_ports = set()   # set[(dpid, port)] of inter-switch ports
        self.local_host_mac = {}  # dpid -> mac
        # -------- Emergency mode state --------
        self.emerg_active = False
        self.emerg_pair = None          # (src_dpid, dst_dpid)
        self.EMERG_COOKIE = 0xE000000000000001  # unique cookie for emergency rules
        self.EMERG_UDP_PORT = 9998

        # Spawn command listener thread
        import threading
        threading.Thread(target=self._emerg_cmd_listener, daemon=True).start()
        self.logger.info("[EMERG] UDP command listener on 0.0.0.0:%d", self.EMERG_UDP_PORT)
        # --- Fast LLDP beacon (for LED heartbeat) ---
        self.fast_lldp_period = 1.0  # istersen 0.5 yapabilirsin
        self.fast_lldp_thread = hub.spawn(self.fast_lldp_loop)
        self.logger.info(f"[BOOT] Fast-LLDP beacon started (period={self.fast_lldp_period}s)")




    # ---------- helpers ----------
    def now(self) -> float:
        return time.time()
    # ---------- FAST LLDP BEACON (for LED heartbeat) ----------
    

    def _iter_physical_ports(self, dp):
        """Return generator of physical port numbers (excludes LOCAL and specials)."""
        ofp = dp.ofproto
        ports = getattr(dp, "ports", {})
        for port_no, ofp_port in ports.items():
            try:
                if 0 < port_no < ofp.OFPP_MAX and port_no != ofp.OFPP_LOCAL:
                    return_port = int(port_no)
                    yield return_port
            except Exception:
                continue
    def program_ipv6_drop(self):
        COOKIE_V6_DROP = 0xA1A2A3A400000006
        for dpid, dp in self.datapaths.items():
            parser, ofp = dp.ofproto_parser, dp.ofproto
            # Eski kuralı sil
            mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                    match=parser.OFPMatch(eth_type=0x86DD),
                                    cookie=COOKIE_V6_DROP, cookie_mask=0xFFFFFFFFFFFFFFFF,
                                    table_id=ofp.OFPTT_ALL)
            dp.send_msg(mod)
            # Yeni: IPv6 drop (prio 2, table-miss'ten yüksek)
            fm = parser.OFPFlowMod(datapath=dp, priority=2,
                                match=parser.OFPMatch(eth_type=0x86DD),
                                instructions=[], cookie=COOKIE_V6_DROP)
            dp.send_msg(fm)
            self.logger.info(f"[V6-DROP] DPID={dp.id} IPv6 drop installed")

    def program_arp_ingress_rules(self):
        """Edge portlardan gelen ARP'yi CONTROLLER'a mirrora et; inter-switch portlardan gelen ARP'yi drop et.
        Böylece BFS ile enjekte ettiğimiz ARP kopyaları tekrar PacketIn oluşturmaz, flapping biter."""
        """Edge portlardan gelen ARP -> CONTROLLER; inter-switch (uplink) ARP -> DROP; LOCAL -> CONTROLLER."""
        COOKIE_ARP_ING = 0xA1A2A3A400000001

        for dpid, dp in self.datapaths.items():
            parser, ofp = dp.ofproto_parser, dp.ofproto

            # Eski kuralları temizle
            mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                    match=parser.OFPMatch(),
                                    cookie=COOKIE_ARP_ING, cookie_mask=0xFFFFFFFFFFFFFFFF,
                                    table_id=ofp.OFPTT_ALL)
            dp.send_msg(mod)

            # LOCAL -> CONTROLLER (Linux host'tan gelen ARP)
            match = parser.OFPMatch(in_port=ofp.OFPP_LOCAL, eth_type=0x0806)
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            flow = parser.OFPFlowMod(datapath=dp, priority=3, match=match,
                                    instructions=inst, cookie=COOKIE_ARP_ING)
            dp.send_msg(flow)

            # Edge fiziksel portlar -> CONTROLLER
            for p in self.edge_ports(dpid):
                match = parser.OFPMatch(in_port=p, eth_type=0x0806)
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                flow = parser.OFPFlowMod(datapath=dp, priority=2, match=match,
                                        instructions=inst, cookie=COOKIE_ARP_ING)
                dp.send_msg(flow)

            # Uplink (inter-switch) portlar -> DROP
            uplinks = {pt for (sw, pt) in self.link_ports if sw == dpid}
            for p in uplinks:
                match = parser.OFPMatch(in_port=p, eth_type=0x0806)
                inst = []  # drop
                flow = parser.OFPFlowMod(datapath=dp, priority=2, match=match,
                                        instructions=inst, cookie=COOKIE_ARP_ING)
                dp.send_msg(flow)

            self.logger.info(f"[ARP-ING] DPID={dp.id} local->ctrl, edge->ctrl, uplink->drop kuruldu")


    def _send_fast_lldp_once(self, dp, port_no):
        """Build & send one LLDP frame out of given port via PacketOut."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        # Port MAC’i varsa kullan; yoksa dummy MAC da iş görür (LED agent sadece 'dpid:' arıyor).
        try:
            hw_addr = dp.ports[port_no].hw_addr
        except Exception:
            hw_addr = "02:00:00:00:00:01"

        # Ryu’nun hazır helper’ı: 'dpid:%016x' içeren LLDP üretir
        pkt = topo_switches.LLDPPacket.lldp_packet(dpid, port_no, hw_addr)
        data = pkt.data

        actions = [parser.OFPActionOutput(port_no)]
        out = parser.OFPPacketOut(datapath=dp,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
        dp.send_msg(out)

    def fast_lldp_loop(self):
        """Periodically send LLDP out of every physical port on every switch."""
        self.logger.info(f"[FAST-LLDP] Beacon loop started (period={self.fast_lldp_period}s)")
        while True:
            try:
                for dpid, dp in list(self.datapaths.items()):
                    for pno in self._iter_physical_ports(dp):
                        try:
                            self._send_fast_lldp_once(dp, pno)
                        except Exception as e:
                            self.logger.debug(f"[FAST-LLDP] send fail dpid={dpid} port={pno}: {e}")
            except Exception as e:
                self.logger.warning(f"[FAST-LLDP] loop error: {e}")
            hub.sleep(self.fast_lldp_period)

    def edge_ports(self, dpid):
        dp = self.datapaths.get(dpid)
        if not dp: return set()
        ofp = dp.ofproto
        phys = {pno for pno in getattr(dp, "ports", {}).keys()
                if isinstance(pno, int) and 0 < pno < ofp.OFPP_MAX and pno != ofp.OFPP_LOCAL}
        uplinks = {p for (sw, p) in self.link_ports if sw == dpid}
        return phys - uplinks


    def arp_broadcast_tree(self, src_dpid, in_port_on_src, data):
        """Loopsuz ARP yayını: BFS ağacı; her node'da ÇOCUK kenarlara + OFPP_LOCAL + edge portlara kopyala."""
        import networkx as nx
        T = nx.bfs_tree(self.topology, source=src_dpid)  # directed parent->child

        for u in T.nodes():
            dp = self.datapaths.get(u)
            if not dp:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto

            parent = next(iter(T.predecessors(u)), None) if hasattr(T, "predecessors") else None
            parent_port = self.topology[u][parent]['port'] if parent and self.topology.has_edge(u, parent) else None

            out_ports = set()

            # Çocuklara giden kenarlar
            for v in T.successors(u):
                out_ports.add(self.topology[u][v]['port'])

            # Bu switch'in host-facing edge portları (varsa)
            out_ports |= self.edge_ports(u)

            # LOCAL'a da ver ki o switch'teki Linux host ARP'yi görebilsin
            out_ports.add(ofp.OFPP_LOCAL)

            # Kökte giriş portunu çıkar
            if u == src_dpid and in_port_on_src in out_ports:
                out_ports.remove(in_port_on_src)
            # Parent kenarı geri göndermeyi engelle
            if parent_port in out_ports:
                out_ports.remove(parent_port)

            if not out_ports:
                continue

            actions = [parser.OFPActionOutput(p) for p in sorted(out_ports)]
            out = parser.OFPPacketOut(datapath=dp,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    in_port=ofp.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=data)
            dp.send_msg(out)
            self.logger.debug(f"[ARP-TREE] DPID={u} fanout={sorted(out_ports)}")


    def update_topology(self):
        self.topology.clear()
        self.link_ports.clear()
        switches = get_switch(self, None)
        links = get_link(self, None)

        for sw in switches:
            dpid = sw.dp.id
            self.topology.add_node(dpid)
            self.datapaths[dpid] = sw.dp

        for lk in links:
            self.topology.add_edge(lk.src.dpid, lk.dst.dpid, port=lk.src.port_no)
            self.topology.add_edge(lk.dst.dpid, lk.src.dpid, port=lk.dst.port_no)
            self.link_ports.add((lk.src.dpid, lk.src.port_no))
            self.link_ports.add((lk.dst.dpid, lk.dst.port_no))
            t = self.now()
            self.link_last_seen[(lk.src.dpid, lk.dst.dpid)] = t
            self.link_last_seen[(lk.dst.dpid, lk.src.dpid)] = t

        # ❗ edge→link dönüşen portlarda yanlış öğrenmeleri sil
        for dpid, macmap in list(self.mac_to_port.items()):
            for mac, p in list(macmap.items()):
                if (dpid, p) in self.link_ports and p != self.datapaths[dpid].ofproto.OFPP_LOCAL:
                    macmap.pop(mac, None)
                    self.mac_to_loc.pop(mac, None)
                    self.logger.info(f"[UNLEARN] DPID={dpid} mac={mac} removed (became inter-switch)")
        self.program_arp_ingress_rules()
        for sw in sorted(self.topology.nodes()):
            self.logger.info(f"[PORTSETS] DPID={sw} edge={sorted(self.edge_ports(sw))} uplinks={sorted([p for (s,p) in self.link_ports if s==sw])}")  
        self.program_ipv6_drop()  



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
            
    def _is_edge_port(self, dpid, port_no):
        dp = self.datapaths.get(dpid)
        if not dp:
            return False
        ofp = dp.ofproto
        if port_no == ofp.OFPP_LOCAL:
            return True
        return self._is_physical_port(dp, port_no) and (dpid, port_no) not in self.link_ports

    def remove_flows_outport(self, dp, out_port):
        """On the given switch, delete flows from ALL tables that use the specified out_port."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # match boş => tüm eşleşmeler; out_port filtresi ile sadece bu porta çıkanlar silinir
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=out_port,
            out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
            table_id=ofp.OFPTT_ALL
        )
        dp.send_msg(mod)
        self.logger.warning(f"[CLEANUP] DPID={dp.id} out_port={out_port} flows are deleted.")



    def print_hosts(self):
        if not self.mac_to_loc:
            self.logger.info("[HOSTS] (none learned yet)")
            return
        self.logger.info("[HOSTS] Learned endpoints:")
        for mac, (dpid, port) in self.mac_to_loc.items():
            last = self.host_last_seen.get(mac)
            self.logger.info(f"[HOSTS] mac={mac} at DPID={dpid} PORT={port} last_seen={last}")

    def learn_host(self, dpid, src_mac, in_port):
        dp = self.datapaths.get(dpid)
        if not dp:
            self.logger.debug(f"[LEARN-SKIP] DPID={dpid} not in datapaths yet")
            return
        ofp = dp.ofproto
        if in_port == ofp.OFPP_LOCAL:
            if dpid not in self.local_host_mac:
                self.local_host_mac[dpid] = src_mac
                self.logger.info(f"[LOCAL-HOST] DPID={dpid} local_mac={src_mac} learned")
            if src_mac != self.local_host_mac[dpid]:
                self.logger.debug(f"[LEARN-SKIP] DPID={dpid} mac={src_mac} on LOCAL (not local host)")
                return
        elif not self._is_edge_port(dpid, in_port):
            self.logger.debug(f"[LEARN-SKIP] DPID={dpid} mac={src_mac} IN={in_port} (not edge)")
            return

        self.mac_to_port.setdefault(dpid, {})
        prev = self.mac_to_port[dpid].get(src_mac)
        self.mac_to_port[dpid][src_mac] = in_port
        self.mac_to_loc[src_mac] = (dpid, in_port)
        self.host_last_seen[src_mac] = self.now()
        if prev != in_port:
            self.logger.info(f"[LEARN] DPID={dpid} mac={src_mac} IN={in_port} (was: {prev})")

    def add_drop_flow_pair(self, dp, src_mac, dst_mac,
                           priority=110, eth_type=0x0800, ip_proto=6,
                           idle_timeout=0, hard_timeout=0, cookie=0):
        """
        src_mac -> dst_mac eşleşmesi için drop (aksiyon yok). 
        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac,
                                eth_type=eth_type, ip_proto=ip_proto)
        inst = []  # no actions => drop

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            cookie=cookie
        )
        dp.send_msg(mod)
        self.logger.info(f"[DROP] DPID={dp.id} ({src_mac}->{dst_mac}) ip_proto={ip_proto} cookie=0x{cookie:016x} prio={priority}")

    def remove_flows_by_cookie(self, dp, cookie):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
            cookie=cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=ofp.OFPTT_ALL
        )
        dp.send_msg(mod)
        self.logger.info(f"[CLEANUP] DPID={dp.id} delete flows cookie=0x{cookie:016x}")

    def _emerg_cmd_listener(self):
        """
        UDP commands:
          - 'EMERG ON <src_dpid> <dst_dpid>'
          - 'EMERG OFF'
        """
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.EMERG_UDP_PORT))
        sock.settimeout(1.0)
        self.logger.info("[EMERG] Listening UDP on 0.0.0.0:%d", self.EMERG_UDP_PORT)
        while True:
            try:
                data, addr = sock.recvfrom(256)
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"[EMERG] Listener error: {e}")
                break

            msg = data.decode(errors="ignore").strip().upper()
            parts = msg.split()
            if len(parts) == 0:
                continue

            if parts[0] == "EMERG" and len(parts) >= 2:
                if parts[1] == "OFF":
                    self.logger.warning(f"[EMERG] OFF requested from {addr[0]}")
                    self._emerg_off()
                elif parts[1] == "ON" and len(parts) == 4:
                    try:
                        s = int(parts[2]); d = int(parts[3])
                        self.logger.warning(f"[EMERG] ON requested: src_dpid={s}, dst_dpid={d} from {addr[0]}")
                        self._emerg_on(s, d)
                    except ValueError:
                        self.logger.error(f"[EMERG] Bad DPIDs in command: {msg}")
                else:
                    self.logger.error(f"[EMERG] Unknown command: '{msg}' from {addr[0]}")
            else:
                self.logger.error(f"[EMERG] Unknown command: '{msg}' from {addr[0]}")


    def _emerg_on(self, src_dpid, dst_dpid):
        self.emerg_active = True
        self.emerg_pair = (src_dpid, dst_dpid)
        self.apply_emergency_policy()

    def _emerg_off(self):
        self.emerg_active = False
        self.emerg_pair = None
        # wipe flows with cookie on all datapaths
        for dp in list(self.datapaths.values()):
            self.remove_flows_by_cookie(dp, self.EMERG_COOKIE)
        self.logger.warning("[EMERG] Policy cleared (flows removed)")

    def apply_emergency_policy(self):
        """
        Build path between the two DPIDs' local host MACs.
        Install high-priority UDP-allow & TCP-drop flows for BOTH directions.
        """
        if not self.emerg_active or not self.emerg_pair:
            self.logger.warning("[EMERG] apply_emergency_policy called but not active/pair unset")
            return

        src_dpid, dst_dpid = self.emerg_pair

        # We need both local host MACs (each Pi's own host MAC learned on OFPP_LOCAL)
        macA = self.local_host_mac.get(src_dpid)
        macB = self.local_host_mac.get(dst_dpid)
        if not macA or not macB:
            self.logger.warning(f"[EMERG] Local host MACs not known yet: {src_dpid}->{macA}, {dst_dpid}->{macB}")
            return

        # path between the SWITCHES (not hosts)
        path = self.get_path(src_dpid, dst_dpid)
        if not path:
            self.logger.error(f"[EMERG] No path between {src_dpid} and {dst_dpid}")
            return

        self.logger.warning(f"[EMERG] Applying between DPID {src_dpid}({macA}) <-> {dst_dpid}({macB}) path={path}")

        # Strategy:
        # 1) Permit UDP (ip_proto=17) along the path (inter-switch hops + edge egress)
        # 2) Drop TCP (ip_proto=6) for macA<->macB on every switch (both directions)
        # Priority: TCP drop (prio 110) > UDP allow (prio 100) > normal L2 rules (prio 10)

        # (1) UDP allow along inter-switch links
        for i in range(len(path) - 1):
            curr = path[i]
            nxt  = path[i + 1]
            outp = self.topology[curr][nxt]['port']
            dp   = self.datapaths[curr]
            # A->B
            self.add_l2_flow(dp, macA, macB, outp, priority=100, ip_proto=17, cookie=self.EMERG_COOKIE)
        # edge egress at destination (A->B)
        dst_sw = path[-1]
        dp_dst = self.datapaths[dst_sw]
        dst_port = self._egress_out_port(dst_sw, macB)
        if dst_port is not None:
            self.add_l2_flow(dp_dst, macA, macB, dst_port, priority=100, ip_proto=17, cookie=self.EMERG_COOKIE)

        # reverse (B->A) inter-switch
        for i in range(len(path) - 1, 0, -1):
            curr = path[i]
            prv  = path[i - 1]
            outp = self.topology[curr][prv]['port']
            dp   = self.datapaths[curr]
            self.add_l2_flow(dp, macB, macA, outp, priority=100, ip_proto=17, cookie=self.EMERG_COOKIE)
        # edge egress at source (B->A)
        src_sw = path[0]
        dp_src = self.datapaths[src_sw]
        src_port = self._egress_out_port(src_sw, macA)
        if src_port is not None:
            self.add_l2_flow(dp_src, macB, macA, src_port, priority=100, ip_proto=17, cookie=self.EMERG_COOKIE)

        # (2) TCP drop for both directions on **every switch** (no actions)
        for sw, dp in self.datapaths.items():
            self.add_drop_flow_pair(dp, macA, macB, priority=110, cookie=self.EMERG_COOKIE)
            self.add_drop_flow_pair(dp, macB, macA, priority=110, cookie=self.EMERG_COOKIE)

        self.logger.warning("[EMERG] Policy installed (UDP allowed, TCP dropped for A<->B)")



    """def flood(self, dp, in_port, data, reason="generic"):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        dp.send_msg(out)
        self.logger.info(f"[FLOOD] DPID={dp.id} IN={in_port} reason={reason}")"""

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

        # Phase 3: mirror only rule
        self.add_arp_flood_rule(dp, priority=1)
        #self.program_arp_ingress_rules()
        #for sw in sorted(self.topology.nodes()):
        #    self.logger.info(f"[PORTSETS] DPID={sw} edge={sorted(self.edge_ports(sw))} uplinks={sorted([p for (s,p) in self.link_ports if s==sw])}")
        self.program_ipv6_drop()


    def _is_physical_port(self, dp, port_no: int) -> bool:
        # Only learn on real ports (exclude LOCAL/CONTROLLER/etc.)
        ofp = dp.ofproto
        # OFPP_MAX is the first reserved (non-physical) port number
        try:
            return 0 < port_no < ofp.OFPP_MAX
        except Exception:
            return False                


    def add_arp_flood_rule(self, dp, priority=1):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0806)  # ARP
        # Sadece controller'a kopyala (FLOOD YOK)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info(f"[FEATURES] ARP mirror→controller installed on DPID={dp.id}")


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
        src = ev.link.src   # src.dpid, src.port_no
        dst = ev.link.dst   # dst.dpid, dst.port_no
        self.logger.warning(f"[LINK] Delete: {src.dpid}:{src.port_no} -X-> {dst.dpid}:{dst.port_no}")

        # Topolojiden kaldır
        if self.topology.has_edge(src.dpid, dst.dpid):
            self.topology.remove_edge(src.dpid, dst.dpid)
        if self.topology.has_edge(dst.dpid, src.dpid):
            self.topology.remove_edge(dst.dpid, src.dpid)

        # Inter-switch port setinden kaldır
        self.link_ports.discard((src.dpid, src.port_no))
        self.link_ports.discard((dst.dpid, dst.port_no))

        # Bu linkin "en son görüldü" izlerini sil
        self.link_last_seen.pop((src.dpid, dst.dpid), None)
        self.link_last_seen.pop((dst.dpid, src.dpid), None)

        # İki uçta da ilgili out_port'u kullanan flow'ları temizle
        dp_src = self.datapaths.get(src.dpid)
        dp_dst = self.datapaths.get(dst.dpid)
        if dp_src:
            self.remove_flows_outport(dp_src, src.port_no)
        if dp_dst:
            self.remove_flows_outport(dp_dst, dst.port_no)

        # Eğer edge port'a yanlışlıkla host öğrenildiyse (mesela topoloji değiştiyse) temizle
        # (inter-switch'e dönüşmüş olamaz çünkü link silindi; gene de tutarlılık için)
        for dpid, port in [(src.dpid, src.port_no), (dst.dpid, dst.port_no)]:
            macmap = self.mac_to_port.get(dpid, {})
            to_unlearn = [m for m, p in macmap.items() if p == port]
            for m in to_unlearn:
                macmap.pop(m, None)
                self.mac_to_loc.pop(m, None)
                self.logger.info(f"[UNLEARN] DPID={dpid} mac={m} removed (port {port} değişti/koptu)")

        self.print_topology("After link delete")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofp = dp.ofproto
        port = msg.desc
        port_no = port.port_no

        # RYU/OF 1.3: reason = ADD/MODIFY/DELETE
        # Link-down genelde MODIFY ve state bitinde OFPPS_LINK_DOWN ile gelir.
        state_down = bool(port.state & ofp.OFPPS_LINK_DOWN)

        if reason == ofp.OFPPR_DELETE or (reason == ofp.OFPPR_MODIFY and state_down):
            self.logger.warning(f"[PORT] DOWN dpid={dp.id} port={port_no} (reason={'DELETE' if reason==ofp.OFPPR_DELETE else 'MODIFY/LINK_DOWN'})")

            # Inter-switch setinden çıkar
            self.link_ports.discard((dp.id, port_no))

            # Bu porta çıkan bütün akışları sil
            self.remove_flows_outport(dp, port_no)

            # Bu portta yanlış host-öğrenmeleri varsa temizle
            macmap = self.mac_to_port.get(dp.id, {})
            to_unlearn = [m for m, p in macmap.items() if p == port_no]
            for m in to_unlearn:
                macmap.pop(m, None)
                self.mac_to_loc.pop(m, None)
                self.logger.info(f"[UNLEARN] DPID={dp.id} mac={m} removed (port {port_no} DOWN)")

        elif reason == ofp.OFPPR_ADD or (reason == ofp.OFPPR_MODIFY and not state_down):
            self.logger.info(f"[PORT] UP dpid={dp.id} port={port_no}")
            # LLDP ile link tekrar keşfedilecek → EventLinkAdd tetiklenince topoloji/flows yeniden oluşur.
            # Burada ekstra bir şey yapmaya gerek yok.

    # ---------- SPF helpers ----------
    def get_path(self, src_dpid, dst_dpid):
        try:
            return nx.shortest_path(self.topology, src_dpid, dst_dpid)
        except nx.NetworkXNoPath:
            return None

    def _egress_out_port(self, sw, mac):
    # LOCAL sadece yerel MAC için
        if sw in self.local_host_mac and mac == self.local_host_mac[sw]:
            return self.datapaths[sw].ofproto.OFPP_LOCAL
        # değilse öğrenilmiş fiziksel edge port
        return self.mac_to_port.get(sw, {}).get(mac)

    def flood_edge_only(self, dp, in_port, data, include_local=False, reason="flood_edge"):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dpid = dp.id

        # 1) Bilinen host edge portları
        ports = set(self.mac_to_port.get(dpid, {}).values())

        # 2) LOCAL'ı isteğe bağlı ekle/çıkar
        if include_local:
            ports.add(ofp.OFPP_LOCAL)
        else:
            if ofp.OFPP_LOCAL in ports:
                ports.remove(ofp.OFPP_LOCAL)

        # 3) Giriş portunu çıkar
        if in_port in ports:
            ports.remove(in_port)

        # 4) BOOTSTRAP: Ports hâlâ boşsa inter-switch link portlarına da fanout yap
        if not ports:
            # Bu DPID'e ait tüm link portlarını topla
            uplinks = {p for (sw, p) in self.link_ports if sw == dpid}
            # Giriş portunu hariç tut
            if in_port in uplinks:
                uplinks.remove(in_port)
            ports |= uplinks

        # 5) Aksiyonları hazırla
        actions = [parser.OFPActionOutput(p) for p in sorted(ports)]

        # 6) Hâlâ boşsa son çare: CONTROLLER yerine istersen hiç göndermemeyi de seçebilirsin,
        # ama mevcut davranışı koruyalım:
        if not actions:
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)
        self.logger.info(f"[FLOOD-EDGE] DPID={dp.id} fanout={sorted(list(ports))} reason={reason}")




    def add_l2_flow(self, dp, src_mac, dst_mac, out_port,
                priority=10, eth_type=0x0800, ip_proto=None,
                idle_timeout=60, hard_timeout=0, cookie=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        kwargs = {"eth_src": src_mac, "eth_dst": dst_mac, "eth_type": eth_type}
        if ip_proto is not None:
            kwargs["ip_proto"] = ip_proto

        match = parser.OFPMatch(**kwargs)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            cookie=cookie
        )
        dp.send_msg(mod)

        self.logger.info(
            f"[FLOW] DPID={dp.id} OUT={out_port} "
            f"({src_mac}->{dst_mac}, eth_type=0x{eth_type:04x}"
            f"{', ip_proto=' + str(ip_proto) if ip_proto is not None else ''}, "
            f"idle={idle_timeout}, cookie=0x{cookie:016x}, prio={priority})"
        )


    def install_path_flows(self, path, src_mac, dst_mac):
        """
        Inter-switch + edge egress rules (both directions).
        path: [sw_a, sw_b, ..., sw_z]
        """
        self.logger.info(f"[PATH] {path}")

        # ---- forward (src -> dst) on inter-switch links ----
        for i in range(len(path) - 1):
            curr = path[i]
            nxt  = path[i + 1]
            out_port = self.topology[curr][nxt]['port']
            dp = self.datapaths[curr]
            self.add_l2_flow(dp, src_mac, dst_mac, out_port)

        # ---- edge egress on destination switch ----
        dst_sw = path[-1]
        dp_dst = self.datapaths[dst_sw]
        dst_port = self._egress_out_port(dst_sw, dst_mac)  # LOCAL dahil
        if dst_port is not None:
            self.add_l2_flow(dp_dst, src_mac, dst_mac, dst_port)
            self.logger.info(f"[EDGE→DST] DPID={dst_sw} OUT={dst_port} ({src_mac} -> {dst_mac})")
        else:
            self.logger.warning(f"[EDGE→DST] DPID={dst_sw}: unknown port for {dst_mac}; first packet will be flooded.")

        # ---- reverse (dst -> src) inter-switch ----
        for i in range(len(path) - 1, 0, -1):
            curr = path[i]
            prv  = path[i - 1]
            out_port = self.topology[curr][prv]['port']
            dp = self.datapaths[curr]
            self.add_l2_flow(dp, dst_mac, src_mac, out_port)

        # ---- edge egress on source switch (for return traffic) ----
        src_sw = path[0]
        dp_src = self.datapaths[src_sw]
        src_port = self._egress_out_port(src_sw, src_mac)  # LOCAL dahil
        if src_port is not None:
            self.add_l2_flow(dp_src, dst_mac, src_mac, src_port)
            self.logger.info(f"[EDGE→SRC] DPID={src_sw} OUT={src_port} ({dst_mac} -> {src_mac})")
        else:
            self.logger.warning(f"[EDGE→SRC] DPID={src_sw}: unknown port for {src_mac}; return may flood initially.")



    # ---------- packet-in ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        # Ignore IPv6 (noise from OS)
        if eth.ethertype == 0x86DD:
            return

        # Learn source on every packet
        self.learn_host(dp.id, eth.src, in_port)

        # ARP?
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_ip, src_mac = arp_pkt.src_ip, eth.src
            self.ip_to_mac[src_ip] = src_mac
            self.learn_host(dp.id, eth.src, in_port)

            # PROXY-ARP: Request ve hedefi biliyorsak direkt yanıtla
            if arp_pkt.opcode == arp.ARP_REQUEST:
                target_ip = arp_pkt.dst_ip
                dst_mac = self.ip_to_mac.get(target_ip)
                if dst_mac and (dst_mac in self.mac_to_loc):
                    # ARP reply paketini oluştur
                    rep = packet.Packet()
                    rep.add_protocol(ethernet.ethernet(dst=eth.src, src=dst_mac,
                                                    ethertype=ether_types.ETH_TYPE_ARP))
                    rep.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                            src_mac=dst_mac, src_ip=target_ip,
                                            dst_mac=eth.src, dst_ip=src_ip))
                    rep.serialize()
                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                            in_port=ofp.OFPP_CONTROLLER,
                                            actions=actions, data=rep.data)
                    dp.send_msg(out)
                    self.logger.info(f"[ARP] Proxy-ARP {target_ip} → {src_ip} on DPID={dp.id}")
                    return

            # Aksi halde loopsuz yayın ağacına ver
            self.arp_broadcast_tree(dp.id, in_port, msg.data)
            self.print_hosts()
            return



        # IPv4?
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            src_mac = eth.src

            # learn
            self.ip_to_mac[src_ip] = src_mac

            # Destination MAC biliniyor mu?
            if dst_ip in self.ip_to_mac:
                dst_mac_known = self.ip_to_mac[dst_ip]

                # Hedef MAC’in nerede olduğunu biliyor muyuz?
                if dst_mac_known in self.mac_to_loc:
                    dst_sw, _ = self.mac_to_loc[dst_mac_known]

                    # >>> YENİ: Kaynak MAC’in gerçek switch’i (varsa) <<<
                    if src_mac in self.mac_to_loc:
                        src_sw, _ = self.mac_to_loc[src_mac]
                    else:
                        src_sw = dp.id  # fallback

                    path = self.get_path(src_sw, dst_sw)
                    if not path:
                        self.logger.warning(f"[PATH] No path from {src_sw} to {dst_sw}; flooding.")
                        self.flood_edge_only(dp, in_port, msg.data, include_local=True, reason="no_path")

                        return

                    # Doğru path üzerinden iki yönlü flow’ları kur
                    self.install_path_flows(path, src_mac, dst_mac_known)

                    # Bu ilk paketi nasıl çıkaracağız?
                    if dp.id == dst_sw:
                        out_port = self._egress_out_port(dp.id, dst_mac_known)
                        if out_port is None:
                            self.logger.warning("[PKT] Same-switch but unknown dst port; flood edge-only.")
                            self.flood_edge_only(dp, in_port, msg.data, include_local=True, reason="dst_same_sw_unknown_port")
                            return
                    elif dp.id in path:
                        # Eğer bu PacketIn path üzerindeki bir switch’teyse, sıradaki hop’a gönder
                        idx = path.index(dp.id)
                        if idx < len(path) - 1:
                            nxt = path[idx + 1]
                            out_port = self.topology[dp.id][nxt]['port']
                        else:
                            # dp.id path’in sonuysa (normalde olmaz)
                            self.logger.info("[PKT] At path end; flooding.")
                            self.flood_edge_only(dp, in_port, msg.data, include_local=True, reason="at_path_end")
                            return
                    else:
                        # PacketIn path dışı bir switch’te; flood et, sonraki paketler kurallara oturur
                        self.logger.info("[PKT] PacketIn off-path; flooding this one.")
                        self.flood_edge_only(dp, in_port, msg.data, include_local=True, reason="off_path")
                        return

                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath=dp,
                                            buffer_id=ofp.OFP_NO_BUFFER,
                                            in_port=in_port,
                                            actions=actions,
                                            data=msg.data)
                    dp.send_msg(out)
                    self.logger.info(f"[PKT] Forwarded first IPv4 packet DPID={dp.id} OUT={out_port} {src_ip}->{dst_ip}")
                    return
                else:
                    self.logger.info(f"[IPv4] dst MAC known ({dst_mac_known}) but location unknown; flooding.")
        
                    return
            else:
                self.logger.info(f"[IPv4] dst IP unknown ({dst_ip}); flooding to discover.")
                
                return


        # Others
        self.logger.info(f"[PKT-IN] DPID={dp.id} IN={in_port} eth_type=0x{eth.ethertype:04x} "
                         f"src={eth.src} dst={eth.dst} (no handler)")
