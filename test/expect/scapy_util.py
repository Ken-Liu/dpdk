""" parse header info from Scapy packet """
""" tmp={}; exec open("test/expect/scapy_util.py") in tmp;  tmp["scapy_info"](Ether()/Dot1Q()/IPv6()/TCP()/GRE()/IP()/UDP()/"abc") """
L3_TYPES = {IP:1, IPv6:2}
L4_TYPES = {TCP:1, SCTP:2, UDP:3}
TUNNEL_TYPES = {VXLAN:1, GRE:2} # VXLAN-GPE:6
end_types = {NoPayload, Raw}
def scapy_info(pkt):
    l2_len=0;
    l3_len=0;
    l4_len=0;
    outer_l3_len = 0;
    outer_l2_len = 0;
    outer_l3_type = 0; 
    outer_l4_type = 0;
    l3_type = 0;
    l4_type = 0;
    tunnel_type = 0;
    sz = 0; 
    
    while(pkt and isinstance(pkt, Packet)):
        print(pkt.__class__)
        if (pkt.__class__ in L3_TYPES):
            l3_type = L3_TYPES[pkt.__class__];
        if (pkt.__class__ in L4_TYPES):
            l4_type = L4_TYPES[pkt.__class__]
        if (pkt.__class__ in TUNNEL_TYPES):
            tunnel_type = TUNNEL_TYPES[pkt.__class__]
            if (isinstance(pkt, VXLAN) and pkt.NextProtocol > 0): 
                tunnel_type = 6; #vxlan-gpe
            outer_l2_len = l2_len;
            outer_l3_len = l3_len;
            l2_len = l4_len;
            l3_len = 0;
            l4_len = 0;
            outer_l3_type = l3_type;
            outer_l4_type = l4_type;
            l3_type = 0;
            l4_type = 0;
        if (pkt.__class__ in end_types):
            break;
        sz = len(pkt.self_build());
        pkt = pkt.payload
        if (l4_type > 0):
            l4_len += sz;
        else:
            if (l3_type > 0):
                l3_len += sz;
            else:
                l2_len += sz;
    return (outer_l3_type, outer_l4_type, l3_type, l4_type, tunnel_type, outer_l2_len, outer_l3_len, l2_len, l3_len, l4_len)

print scapy_info(Ether()/IPv6()/UDP()/VXLAN()/IP()/TCP()/'abc');
