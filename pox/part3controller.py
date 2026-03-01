# Part 3 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr, IPAddr6

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

ROUTING_TABLE = {
    "10.0.1.0/24": 1,
    "10.0.2.0/24": 2,
    "10.0.3.0/24": 3,
    "10.0.4.0/24": 4,
    "172.16.10.0/24": 5,
}


class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)

        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        self._install_flood_rule()

    def s2_setup(self):
        self._install_flood_rule()

    def s3_setup(self):
        self._install_flood_rule()

    def cores21_setup(self):
        # Block ICMP from Untrusted Host.
        message = of.ofp_flow_mod()
        message.priority = 100
        message.match.dl_type = 0x0800
        message.match.nw_proto = 1
        message.match.nw_src = IPS["hnotrust"]
        self.connection.send(message)

        # Block all IP from Untrusted Host to Server.
        message = of.ofp_flow_mod()
        message.priority = 100
        message.match.dl_type = 0x0800
        message.match.nw_src = IPS["hnotrust"]
        message.match.nw_dst = IPS["serv1"]
        self.connection.send(message)

        # Routing Rules
        for subnet, port in ROUTING_TABLE.items():
            message = of.ofp_flow_mod()
            message.priority = 10
            message.match.dl_type = 0x0800
            message.match.nw_dst = subnet
            message.actions.append(of.ofp_action_output(port=port))
            self.connection.send(message)

    def dcs31_setup(self):
        self._install_flood_rule()

    def _install_flood_rule(self):
        message = of.ofp_flow_mod()
        message.priority = 1
        message.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(message)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
