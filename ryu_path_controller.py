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
        self.net = {}  # Topology graph (adjacency list)

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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = msg.data
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Basit MAC öğrenme:
        eth_src = msg.data[6:12]
        eth_dst = msg.data[0:6]

        # MAC adreslerini hex olarak alın:
        src_mac = ':'.join(['%02x' % b for b in eth_src])
        dst_mac = ':'.join(['%02x' % b for b in eth_dst])

        self.mac_to_port.setdefault(dpid, {})

        # Kaynağı öğren
        self.mac_to_port[dpid][src_mac] = in_port
        self.logger.info("Switch %s learned MAC %s at port %s", dpid, src_mac, in_port)

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)