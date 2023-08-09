# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def drop(self, packet, packet_in):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout =60
    msg.hard_timeout=60
    msg.data = packet_in
    self.connection.send(msg)

  def forward(self, packet, packet_in, port):
    print(port)
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout =60
    msg.hard_timeout=60
    msg.actions.append(of.ofp_action_output(port=port))
    msg.data = packet_in
    self.connection.send(msg)

  def go_to_host(self, packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP):
    if switch_id==1:
      if dest_IP == '10.1.1.10':
        self.forward(packet, packet_in, 8)
        return
        #msg.actions.append(of.ofp_action_output(port=8))
      elif dest_IP == '10.1.2.20':
        self.forward(packet, packet_in, 9)
        return
        #msg.actions.append(of.ofp_action_output(port=9))


    elif switch_id==2:
      if dest_IP == '10.1.3.30':
        self.forward(packet, packet_in, 8)
        return
        #msg.actions.append(of.ofp_action_output(port=8))
      elif dest_IP == '10.1.4.40':
        self.forward(packet, packet_in, 9)
        return
       # msg.actions.append(of.ofp_action_output(port=9))

    elif switch_id==5:
      if dest_IP == '10.2.5.50':
        self.forward(packet, packet_in, 8)
        return
       # msg.actions.append(of.ofp_action_output(port=8))
      elif dest_IP == '10.2.6.60':
        self.forward(packet, packet_in, 9)
        return
       # msg.actions.append(of.ofp_action_output(port=9))

    elif switch_id ==6:
      if dest_IP == '10.2.7.70':
        self.forward(packet, packet_in, 8)
        return
        #msg.actions.append(of.ofp_action_output(port=8))
      elif dest_IP == '10.2.8.80':
        self.forward(packet, packet_in, 9)
        return
        #msg.actions.append(of.ofp_action_output(port=9))




  def sent_to_core(self, packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP):
    print("in sent_to_core")
    F1S1 = ['10.1.1.10', '10.1.2.20']
    F1S2 = ['10.1.3.30', '10.1.4.40']
    F2S1 = ['10.2.5.50', '10.2.6.60']
    F2S2 = ['10.2.7.70', '10.2.8.80']

    if source_IP in F1S2 and dest_IP in F1S1:
      self.forward(packet, packet_in, 1)
      #msg.actions.append(of.ofp_action_output(port=1))
      self.go_to_host(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
      return
    elif source_IP in F1S1 and dest_IP in F1S2:
      self.forward(packet, packet_in, 2)
      #msg.actions.append(of.ofp_action_output(port=2))
      self.go_to_host(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
      return

    elif source_IP in F2S2 and dest_IP in F2S1:
      self.forward(packet, packet_in, 3)
      #msg.actions.append(of.ofp_action_output(port=3))
      self.go_to_host(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
      return
    
    elif source_IP in F2S1 and dest_IP in F2S2:
      self.forward(packet, packet_in, 4)
      #msg.actions.append(of.ofp_action_output(port=4))
      self.go_to_host(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
      return
    
    


  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    ip=packet.find('icmp')
    ip1 = packet.find('ipv4')

    F1S1 = ['10.1.1.10', '10.1.2.20']
    F1S2 = ['10.1.3.30', '10.1.4.40']
    F2S1 = ['10.2.5.50', '10.2.6.60']
    F2S2 = ['10.2.7.70', '10.2.8.80']
    server = ['10.3.9.90']
    trust = ['108.24.31.112']
    untrust = ['106.44.82.103']


    if(switch_id==1):
      print("switch1")
      #if not ip:
        #self.drop(packet, packet_in)
       # return
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)
        return
        #msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP in F1S1:
          if dest_IP == '10.1.1.10':
            self.forward(packet, packet_in, 8)
            return
            #msg.actions.append(of.ofp_action_output(port=8))
          elif dest_IP == '10.1.2.20':
            self.forward(packet, packet_in, 9)
            return

        else:
          self.forward(packet, packet_in, 1)
          return
          #msg.actions.append(of.ofp_action_output(port=1))
         
         #don't need...
          #self.sent_to_core(self, packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
          return
    elif(switch_id==3):
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)
        return
      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP in F1S2:
          if source_IP in F1S2 or source_IP in F1S1 or source_IP == '10.3.9.90' or source_IP == '108.24.31.112':
            self.forward(packet, packet_in, 2)
          else:
            if not ip:
              self.forward(packet, packet_in, 2)
            else:
              self.drop(packet, packet_in)
          return
        elif dest_IP in F2S1:
          if source_IP in F2S1 or source_IP in F2S2 or source_IP == '10.3.9.90' or source_IP == '108.24.31.112':
            self.forward(packet, packet_in, 3)
          else:
            if not ip:
              self.forward(packet, packet_in, 3)
            else:
              self.drop(packet, packet_in)
          return
        elif dest_IP in F2S2:
          if source_IP in F2S1 or source_IP in F2S2 or source_IP == '10.3.9.90' or source_IP == '108.24.31.112':
            self.forward(packet, packet_in, 4)
          else:
            if not ip:
              self.forward(packet, packet_in, 4)
            else:
              self.drop(packet, packet_in)

          return
        elif dest_IP in F1S1:
          if source_IP in F1S2 or source_IP in F1S1 or source_IP == '10.3.9.90' or source_IP == '108.24.31.112':
            print("Forwarding to 1")
            self.forward(packet, packet_in, 1)
          else:
            if not ip:
              self.forward(packet, packet_in, 1)
            else:
              self.drop(packet, packet_in)
              
          return
        #server
        #if going to server and coming from untrusted or trusted host
        elif dest_IP in server:
          print("in server")
          if source_IP in untrust:
            self.drop(packet, packet_in)
          if source_IP in trust:
            self.drop(packet, packet_in)
          else:
            print("working")
            self.forward(packet, packet_in, 5)

          return

        elif dest_IP in trust:
          if source_IP in F1S1 or source_IP in F1S2:
            self.forward(packet, packet_in, 6)
          else:
            self.drop(packet, packet_in)
          
        elif dest_IP in untrust:
          if ip:
            self.drop(packet, packet_in)
        # elif source_IP in untrust:
        #   if not ip:
        #     self.drop()
        #   else:
        #     self.drop()
        #     return
        # elif source_IP in trust:
        #   if ip:
        #     if dest_IP in F1S1:
        #       self.forward(packet, packet_in, 1)
        #     if dest_IP in F1S2:
        #       self.forward(packet, packet_in, 2)
        #     else:
        #       self.drop()
        #       return

        #   else:
        #     self.drop()
        #     return



            

        


          

    elif (switch_id ==2):
      print("switch 2")
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)
        #msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP in F1S2: #and source_IP in F1S2:
          if dest_IP == '10.1.3.30':
            self.forward(packet, packet_in, 8)
            return
            #msg.actions.append(of.ofp_action_output(port=9))
          elif dest_IP == '10.1.4.40':
            self.forward(packet, packet_in, 9)
            return
            #msg.actions.append(of.ofp_action_output(port=8))
        else:
          self.forward(packet, packet_in, 1)
          #msg.actions.append(of.ofp_action_output(port=1))
          #self.sent_to_core(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
          return

    elif (switch_id ==5):
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)
        #msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP in F2S1:
          if dest_IP == '10.2.5.50':
            self.forward(packet, packet_in, 8)
            return
            #msg.actions.append(of.ofp_action_output(port=8))
          elif dest_IP == '10.2.6.60':
            self.forward(packet, packet_in, 9)
            return
            #msg.actions.append(of.ofp_action_output(port=9))
        else:
          self.forward(packet, packet_in, 1)
          #msg.actions.append(of.ofp_action_output(port=1))
          #self.sent_to_core(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
          return

    elif(switch_id==4):
      print("switch 4")
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)

      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP == '10.3.9.90':
          self.forward(packet, packet_in, 8)
          return
        else:
          self.forward(packet, packet_in, 1)
          return
              


    elif (switch_id ==6):
      if not ip1:
        self.forward(packet, packet_in, of.OFPP_FLOOD)
        #msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      else:
        dest_IP = str(ip1.dstip)
        source_IP = str(ip1.srcip)
        if dest_IP in F2S2:
          if dest_IP == '10.2.7.70':
            self.forward(packet, packet_in, 8)
            return
            # msg.actions.append(of.ofp_action_output(port=8))
          elif dest_IP == '10.2.8.80':
            self.forward(packet, packet_in, 9)
            return
            #msg.actions.append(of.ofp_action_output(port=9))
        else:
          self.forward(packet, packet_in, 1)
            #msg.actions.append(of.ofp_action_output(port=1))
          #self.sent_to_core(packet, packet_in, port_on_switch, switch_id, source_IP, dest_IP)
          return
            




  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
