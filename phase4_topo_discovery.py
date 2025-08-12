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


    # ---------- helpers ----------
    def now(self) -> float:
        return time.time()

    def update_topology(self):
        """Rebuild the DiGraph from Ryu's snapshot APIs."""
        self.topology.clear()
        self.link_ports.clear()                       # ← EKLE
        switches = get_switch(self, None)
        links = get_link(self, None)

        for sw in switches:
            dpid = sw.dp.id
            self.topology.add_node(dpid)
            self.datapaths[dpid] = sw.dp

        for lk in links:
            self.topology.add_edge(lk.src.dpid, lk.dst.dpid, port=lk.src.port_no)
            self.topology.add_edge(lk.dst.dpid, lk.src.dpid, port=lk.dst.port_no)
            # mark inter-switch ports
            self.link_ports.add((lk.src.dpid, lk.src.port_no))
            self.link_ports.add((lk.dst.dpid, lk.dst.port_no))
            t = self.now()
            self.link_last_seen[(lk.src.dpid, lk.dst.dpid)] = t
            self.link_last_seen[(lk.dst.dpid, lk.src.dpid)] = t


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
    def _is_edge_port(self, dpid: int, port_no: int) -> bool:
        dp = self.datapaths.get(dpid)
        if not dp:
            return False
        ofp = dp.ofproto
        # Host aynı makinedeyse LOCAL’dan gelir → edge kabul et
        if port_no == ofp.OFPP_LOCAL:
            return True
        # Diğer durum: fiziksel ve inter-switch değilse edge
        return self._is_physical_port(dp, port_no) and (dpid, port_no) not in self.link_ports


    def print_hosts(self):
        if not self.mac_to_loc:
            self.logger.info("[HOSTS] (none learned yet)")
            return
        self.logger.info("[HOSTS] Learned endpoints:")
        for mac, (dpid, port) in self.mac_to_loc.items():
            last = self.host_last_seen.get(mac)
            self.logger.info(f"[HOSTS] mac={mac} at DPID={dpid} PORT={port} last_seen={last}")

    def learn_host(self, dpid, src_mac, in_port):
        if not self._is_edge_port(dpid, in_port):    # ← DEĞİŞTİ
            self.logger.debug(f"[LEARN-SKIP] DPID={dpid} mac={src_mac} IN={in_port} (not edge)")
            return
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

        # Phase 3: low-priority ARP flood rule
        self.add_arp_flood_rule(dp, priority=1)

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
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),  # ← mirror to controller
            parser.OFPActionOutput(ofp.OFPP_FLOOD)                               # ← and flood in dataplane
        ]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info(f"[FEATURES] Low-priority ARP mirror+flood installed on DPID={dp.id}")

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

    # ---------- SPF helpers ----------
    def get_path(self, src_dpid, dst_dpid):
        try:
            return nx.shortest_path(self.topology, src_dpid, dst_dpid)
        except nx.NetworkXNoPath:
            return None

    def add_l2_flow(self, dp, src_mac, dst_mac, out_port, priority=10, eth_type=0x0800, ip_proto=None):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        kwargs = {"eth_src": src_mac, "eth_dst": dst_mac, "eth_type": eth_type}
        if ip_proto is not None:
            kwargs["ip_proto"] = ip_proto
        match = parser.OFPMatch(**kwargs)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info(f"[FLOW] DPID={dp.id} OUT={out_port} ({src_mac} -> {dst_mac}, "
                         f"eth_type=0x{eth_type:04x}{', ip_proto='+str(ip_proto) if ip_proto is not None else ''})")

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
        # DEST edge egress
        dst_sw = path[-1]
        dst_port = self.mac_to_port.get(dst_sw, {}).get(dst_mac)
        dp_dst = self.datapaths[dst_sw]
        if dst_port is not None:  # LOCAL dahil
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
        # SRC edge egress (return)
        src_sw = path[0]
        src_port = self.mac_to_port.get(src_sw, {}).get(src_mac)
        dp_src = self.datapaths[src_sw]
        if src_port is not None:  # LOCAL dahil
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
            self.ip_to_mac[arp_pkt.src_ip] = eth.src
            self.logger.info(f"[ARP] src_ip={arp_pkt.src_ip} src_mac={eth.src} op={arp_pkt.opcode}")
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
                        self.flood(dp, in_port, msg.data, reason="no_path")
                        return

                    # Doğru path üzerinden iki yönlü flow’ları kur
                    self.install_path_flows(path, src_mac, dst_mac_known)

                    # Bu ilk paketi nasıl çıkaracağız?
                    if dp.id == dst_sw:
                        out_port = self.mac_to_port[dp.id].get(dst_mac_known)
                        if not out_port:
                            self.logger.warning("[PKT] Same-switch but unknown dst port; flood.")
                            self.flood(dp, in_port, msg.data, reason="dst_same_sw_unknown_port")
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
                            self.flood(dp, in_port, msg.data, reason="at_path_end")
                            return
                    else:
                        # PacketIn path dışı bir switch’te; flood et, sonraki paketler kurallara oturur
                        self.logger.info("[PKT] PacketIn off-path; flooding this one.")
                        self.flood(dp, in_port, msg.data, reason="off_path")
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
                    self.flood(dp, in_port, msg.data, reason="dst_loc_unknown")
                    return
            else:
                self.logger.info(f"[IPv4] dst IP unknown ({dst_ip}); flooding to discover.")
                self.flood(dp, in_port, msg.data, reason="dst_ip_unknown")
                return


        # Others
        self.logger.info(f"[PKT-IN] DPID={dp.id} IN={in_port} eth_type=0x{eth.ethertype:04x} "
                         f"src={eth.src} dst={eth.dst} (no handler)")
