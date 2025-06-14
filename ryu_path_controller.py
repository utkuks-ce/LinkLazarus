# Ryu controller file: ryu_path_controller.py (or whatever you named it)

import os
# Diğer importlar zaten duruyor...
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch, get_all_link
from ryu.topology.event import EventSwitchEnter, EventLinkAdd
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import ether_types


class SimpleTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        
        super(SimpleTopology, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.net = {}
        self.installed_flows = set()

    def is_emergency(self):
        """Emergency flag kontrol edilir."""
        return os.path.exists("/tmp/emergency.flag")

    @set_ev_cls(EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switches = get_all_switch(self)
        self.logger.info("Current switches: %s", [sw.dp.id for sw in switches])

    @set_ev_cls(EventLinkAdd)
    def link_add_handler(self, ev):
        links = get_all_link(self)
        self.logger.info("Current links: %s", [(link.src.dpid, link.dst.dpid) for link in links])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst,
            table_id=0
        )
        datapath.send_msg(mod)
        self.logger.info("📥 Table-miss flow yüklendi (priority=0)")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=30, hard_timeout=0, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                table_id=table_id,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                table_id=table_id,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )

        self.logger.info("📤 FlowMod gönderiliyor: %s", match)
        datapath.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if self.is_emergency():
            self.logger.warning("🚨 Emergency mode active: dropping all packets")
            return

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        eth_type = eth.ethertype
        src_mac = eth.src
        dst_mac = eth.dst

        if eth_type == ether_types.ETH_TYPE_LLDP or dst_mac.startswith("01:80"):
            self.logger.info("🚫 LLDP/STP paketi atlandı.")
            return

        self.logger.info("📥 PacketIn: Switch %s, Port %s, %s ➝ %s", dpid, in_port, src_mac, dst_mac)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        self.logger.info("🧠 MAC Tablosu [%s]: %s", dpid, self.mac_to_port[dpid])

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            flow_key = (dpid, src_mac, dst_mac)

            if flow_key not in self.installed_flows:
                self.logger.info("➕ Yeni flow: %s → %s | Port: %s", src_mac, dst_mac, out_port)
                self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=0)
                self.installed_flows.add(flow_key)
                self.logger.info("✅ Flow eklendi: %s", flow_key)
            else:
                self.logger.info("⏩ Flow zaten var: %s", flow_key)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            self.logger.info("🌊 dst_mac (%s) bilinmiyor, FLOOD.", dst_mac)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
