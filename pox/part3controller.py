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
        # put switch 1 rules here
        pass

    def s2_setup(self):
        # put switch 2 rules here
        pass

    def s3_setup(self):
        # put switch 3 rules here
        pass

    def cores21_setup(self):
        # put core switch rules here
        pass

    def dcs31_setup(self):
        # put datacenter switch rules here
        pass

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

        ip_packet = packet.find("ipv4")
        icmp_packet = packet.find("icmp")

        # Block ICMP traffic from Untrusted Host.
        if icmp_packet and str(icmp_packet.srcip) == IPS["hnotrust"]:
            return

        # Block IP traffic from Untrusted Host to Server 1.
        if (
            ip_packet
            and str(ip_packet.srcip) == IPS["hnotrust"]
            and str(ip_packet.dstip) == IPS["serv1"]
        ):
            return

        in_packet = event.ofp

        # Allow traffic between all hosts.
        match self.connection.dpid:
            # Core Router: Forward to intended destination.
            case 21:
                out_port = 0

                message = of.ofp_packet_out()
                message.data = in_packet.data
                message.actions.append(of.ofp_action_output(port=out_port))

                event.connection.send(message)
                return

            # Secondary Routers: Flood
            case 1 | 2 | 3 | 31:
                message = of.ofp_packet_out()
                message.data = in_packet.data
                message.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

                event.connection.send(message)
                return

            case _:
                print(
                    "Unhandled packet from "
                    + str(self.connection.dpid)
                    + ":"
                    + packet.dump()
                )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
