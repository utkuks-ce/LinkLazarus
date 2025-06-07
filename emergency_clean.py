from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch, get_all_link
from ryu.topology.event import EventSwitchEnter, EventLinkAdd

class SimpleTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleTopology, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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

        # Table-miss: unknown packetleri kontrolöre gönder
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = msg.data
        eth_src = pkt[6:12]
        eth_dst = pkt[0:6]

        src_mac = ':'.join('%02x' % b for b in eth_src)
        dst_mac = ':'.join('%02x' % b for b in eth_dst)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        self.logger.info("Switch %s learned MAC %s at port %s", dpid, src_mac, in_port)

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            actions = [parser.OFPActionOutput(out_port)]

            # MAC'ler öğrenildiyse flow kuralı ekle (artık flood yapılmaz)
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            self.add_flow(datapath, priority=1, match=match, actions=actions)

        else:
            # Hedef MAC bilinmiyor: flood
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        # PacketOut gönder
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
