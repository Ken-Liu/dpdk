Scapy DPDK extension
====================

Scapy DPDK extension is a testpmd forwarding engine and a set of command: tx, rx 
and expect(tx,rx,compare) packet, useful for development, unit test and fast 
regression.


This document introduces basic syntax with examples.

* Scapy usage: http://scapy.readthedocs.io/en/latest/usage.html

Enable python/scapy:
--------------------------------
- Remember to install python-libs and scapy using `yum` or `apt`
- Enable python lib in dpdk configuration, build:

  .. code-block:: c
 
    CONFIG_RTE_LIBRTE_PYTHON=y
    CONFIG_RTE_LIBRTE_PYTHON_VERSION=python2.7

- Start testpmd in interactive mode

TX - send packet out
---------------------
tx <port> <scapy>
~~~~~~~~~~~~~~~~~
.. code-block:: c

  # Continuously send simple packet
  testpmd> tx 0 1

  # Send scapy syntax packet
  testpmd> tx 0 Ether()/IP()/UDP()/"hello"

  # Flush a subnet
  testpmd> tx 0 Ether()/IP(dst="192.168.0.1/24")
  8776640/0 packets sent in 2167534.739us 4.049135mpps

tx <port> <scapy> <count> <verbose>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: text

  # only send 1
  testpmd> tx 0 Ether()/IP()/"hello" 1 0
  1/1 packets sent in 1091.912us 0.000916mpps

  # with simple scapy brief
  testpmd> tx 0 Ether()/IP()/"hello" 1 0x01
  Ether / 127.0.0.1 > 127.0.0.1 ip / Raw / Padding
  1/1 packets sent in 1084.420us 0.000922mpps

  # enum
  testpmd> tx 0 Ether()/IP()/UDP(sport=[54321,54323]) 2 1
  Ether / IP / UDP 127.0.0.1:54321 > 127.0.0.1:domain / Padding
  Ether / IP / UDP 127.0.0.1:54323 > 127.0.0.1:domain / Padding

  # range
  testpmd> tx 0 Ether()/IP()/UDP(sport=(54321,54323)) 3 1
  Ether / IP / UDP 127.0.0.1:54321 > 127.0.0.1:domain / Padding
  Ether / IP / UDP 127.0.0.1:54322 > 127.0.0.1:domain / Padding
  Ether / IP / UDP 127.0.0.1:54323 > 127.0.0.1:domain / Padding

  # generate flows
  testpmd> tx 0 Ether()/IP(dst="10.0.0.1/31")/TCP(dport=(55555,55556)) 4 2
  <Ether  dst=00:00:5e:00:01:19 src=80:18:44:e2:6e:fc type=IPv4 |<IP  ihl=5L len=40 frag=0 proto=tcp chksum=0x990f src=10.12.205.180 dst=10.0.0.0 |<TCP  dport=55555 dataofs=5L chksum=0xd50a |<Padding  load='\x00\x00\x00\x00\x00\x00' |>>>>
  <Ether  dst=00:00:5e:00:01:19 src=80:18:44:e2:6e:fc type=IPv4 |<IP  ihl=5L len=40 frag=0 proto=tcp chksum=0x990f src=10.12.205.180 dst=10.0.0.0 |<TCP  dport=55556 dataofs=5L chksum=0xd509 |<Padding  load='\x00\x00\x00\x00\x00\x00' |>>>>
  <Ether  dst=00:00:5e:00:01:19 src=80:18:44:e2:6e:fc type=IPv4 |<IP  ihl=5L len=40 frag=0 proto=tcp chksum=0x990e src=10.12.205.180 dst=10.0.0.1 |<TCP  dport=55555 dataofs=5L chksum=0xd509 |<Padding  load='\x00\x00\x00\x00\x00\x00' |>>>>
  <Ether  dst=00:00:5e:00:01:19 src=80:18:44:e2:6e:fc type=IPv4 |<IP  ihl=5L len=40 frag=0 proto=tcp chksum=0x990e src=10.12.205.180 dst=10.0.0.1 |<TCP  dport=55556 dataofs=5L chksum=0xd508 |<Padding  load='\x00\x00\x00\x00\x00\x00' |>>>>
  4/4 packets sent in 2923.823us 0.001368mpps
  
RX - receive packet
-------------------
rx <port>
~~~~~~~~~

.. code:: text

  # continuously receive on port 0 until Ctrl+C
  testpmd> rx 0
  6721984/0 packets received in 1163983.125us 5.774984mpps

rx <port> <count> <timeout(s)> <verbose>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: text

  # Receive 1 packet from port 0 with simple dump
  testpmd> rx 0 1 0 1
  Ether / IP / UDP 127.0.0.1:domain > 127.0.0.1:domain / Padding
  1/1 packets received in 2064638.250us 0.000000mpps

  # receive 1 packet with mbuf header, brief and hex dump
  testpmd> rx 0 1 10 0x32
  RX P:0 Q:0 len:60 ptype:0x291 ol_flags:0x180 rss:0x00000000 fdir:0x0
    ptype: L2_ETHER L3_IPV4_EXT_UNKNOWN L4_UDP
    ol_flags: PKT_RX_L4_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
  <Ether  dst=ff:ff:ff:ff:ff:ff src=00:00:00:00:00:00 type=IPv4 |<IP  ihl=5L len=28 frag=0 proto=udp chksum=0x7cce src=127.0.0.1 dst=127.0.0.1 |<UDP  len=8 chksum=0x172 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>>
  0000   FF FF FF FF FF FF 00 00  00 00 00 00 08 00 45 00   ..............E.
  0010   00 1C 00 01 00 00 40 11  7C CE 7F 00 00 01 7F 00   ......@.|.......
  0020   00 01 00 35 00 35 00 08  01 72 00 00 00 00 00 00   ...5.5...r......
  0030   00 00 00 00 00 00 00 00  00 00 00 00               ............
  1/1 packets received in 5180381.000us 0.000000mpps

Expect - send, receive and compare
-------------------------------------
Need one of following topo to get packet back:

  - VF to VF
  - use testpmd io forwarding on remote server of a back-to-back connection
  - set NIC phy in loopback mode
  - use loopback connector on NIC port
  - physical connect two port that DPDK support

expect <tx_port> <rx_port> <scapy>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default timeout: 10ms

.. code:: text

  # basic send
  testpmd> expect 0 0 Ether()  
  tx: 1/1 1.211us 0.825826mpps    rx: 1/1 7.571us 0.132077mpps    round: 1/1 7.571us      total: 7.571us 0.132077mpps

.. code:: text

  # if not recevied:
  testpmd> expect 0 0 Ether()
  Failed tx: 1/1 8.439us 0.118503mpps     rx: 0/1 10006.879us 0.000000mpps        round: 1/1 10006.879us  total: 10006.879us 0.000000mpps

.. code:: text

  # if packet corrupted, auto diff hex:
  testpmd> expect 0 0 Ether()/IP()
  Failed: packet not same:
  0000        FF FF FF FF FF FF 00 00  00 00 00 00 08 00 45 00   ..............E.
       0000   00 00 00 00 00 00 FF FF  FF FF FF FF 08 00 45 00   ..............E.
  0010 0010   00 14 00 01 00 00 40 00  7C E7 7F 00 00 01 7F 00   ......@.|.......
  0020 0020   00 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................
  0030 0030   00 00 00 00 00 00 00 00  00 00 00 00               ............
  RX P:0 Q:0 len:60 ptype:0x691 ol_flags:0x80 rss:0x00000000 fdir:0x0
    ptype: L2_ETHER L3_IPV4_EXT_UNKNOWN L4_NONFRAG
    ol_flags: PKT_RX_L4_CKSUM_UNKNOWN PKT_RX_IP_CKSUM_GOOD
  tx: 1/1 1.494us 0.669507mpps    rx: 1/1 6800.465us 0.000147mpps round: 1/1 6800.465us   total: 6800.465us 0.000147mpps

expect <tx_port> <rx_port> <scapy> <count> <round> <timeout(ms)> <verbose> <field> <val>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: text

  # dump rx header info and assert hw offload flag filed
  testpmd> expect 0 0 Ether()/IP()/UDP() 1 1 1 0x10  ol_flags 0x182
  RX P:0 Q:1 len:60 ptype:0x291 ol_flags:0x182 rss:0xf2279e9d fdir:0x0 ptype: L2_ETHER L3_IPV4_EXT_UNKNOWN L4_UDP
  ol_flags: PKT_RX_RSS_HASH PKT_RX_L4_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
  tx: 1/1 6.240us 0.160256mpps    rx: 1/1 500.597us 0.001998mpps  round: 1/1 500.597us    total: 500.597us 0.001998mpps

Supported field check:

  queue, ptype, rss, fdir, ol_flags, non|0

.. code:: text

  # no packet expect to be received:
  testpmd> expect 0 0 Ether()/IP()/UDP() 0 1 100 0x10  0 0
  tx: 1/1 9.058us 0.110397mpps    rx: 0/0 100041.414us 0.000000mpps       round: 1/1 100041.414us total: 100041.414us 0.000000mpps

  # Fail and auto dump if we do receive one:
  testpmd> expect 0 0 Ether()/IP()/UDP() 0 1 100 0x0  ol_flags 0x182
  RX P:0 Q:1 len:60 ptype:0x291 ol_flags:0x182 rss:0xf2279e9d fdir:0x0
  ptype: L2_ETHER L3_IPV4_EXT_UNKNOWN L4_UDP
  ol_flags: PKT_RX_RSS_HASH PKT_RX_L4_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
  Failed tx: 1/1 5.353us 0.186805mpps     rx: 1/0 100036.852us 0.000010mpps       round: 1/1 100036.852us total: 100036.852us 0.000010mpps

.. code:: bash

  # latency test, tx/rx 10000 rounds
  testpmd> expect 0 0 Ether() 1 10000 1000 0 0 0
  tx: 10000/10000 50401.309us 0.198408mpps        rx: 10000/10000 50406.070us 0.198389mpps        round: 10000/10000 5.041us      total: 50406.070us 0.198389mpps

.. code:: bash

  # tx and rx for 100ms - performance test
  testpmd>  expect 0 1 Ether()/IP()/UDP(sport=(1,255))/("a"*978) 0 1 100 0 0 0
  Failed tx: 114048/0 10003.931us 11.400319mpps   rx: 108894/0 9985.172us 10.905571mpps   round: 1/1 10003.931us  total: 10003.931us 10.885121mpps

<timeout>:

- 0: endless loop, could be canceled by Ctrl+C
- integer: seconds(rx) or msecs(expect)

<verbose>: same to global verbose definition


Verbose level - global output control
----------------------------------------------

- set verbose <level>

.. code:: text

   xxxx xxxx xxxx xxxx
   = == ====  === ====
   | ||  |    |||  L-- RX 0:mute 1:short 2:brief 3:detail
   | ||  |    ||L----- RX header dump
   | ||  |    |L------ RX hex dump
   | ||  |    L------- Mute succeed expect command, for batch running
   | ||  L------------ TX 0:mute 1:short 2:brief 3:detail
   | |L--------------- TX header dump
   | L---------------- TX hex dump
   L------------------ Echo CLI to screen during "load" command

py - call python
---------------- 
py <commands>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Any python grammar allowed:

.. code:: text

  testpmd> py 1+1
  2

  testpmd> py hex(12345)
  '0x3039'

  testpmd> py 0x12345
  74565

  testpmd> py a=Ether();b=UDP();a/IP()/b; a/IPv6()/b
  <Ether  type=IPv4 |<IP  frag=0 proto=udp |<UDP  |>>>
  <Ether  type=IPv6 |<IPv6  nh=UDP |<UDP  |>>>

py shell - enter python shell
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code:: text

  testpmd> py shell
  >>> Help(Ether)
  # "ctrl + d" to quit

py <debug|nodebug>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Toggle python lib debug

PktGen Engine
--------------------
A new engine to tx, rx and compare packets based on templates.

pktgen idle <mode>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Behavior of idle:

- 0 - drop: rx only
- 1 - loopback: rx and send back
- 2 - forward: using testpmd port-queue mapping
- 3 - switch: switch mac address and send back

Batch Test
------------------------

load <file>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

load and run testpmd CLI batch in mute

.. code:: text

  testpmd> load test/expect/init.exp
  Change verbose level from 0 to 64
  Read CLI commands from test/expect/init.exp

  # verify 
  testpmd>py eth
  <Ether  dst=aa:bb:cc:dd:ee:ff src=00:11:22:33:44:55 |>

set verbose 0x8000
~~~~~~~~~~~~~~~~~~~
Set testpmd batch file loading with CLI echo to screen, easy to find source CLI if any error occurs.

.. code:: text

  testpmd> set verbose 0x8000
  testpmd> load test/expect/rx.exp
  testpmd> py eth = Ether(src="00:11:22:33:44:55",dst="aa:bb:cc:dd:ee:ff")
  testpmd> py ethb = Ether(src="00:11:22:33:44:55",dst="ff:ff:ff:ff:ff:ff")
  ...

Known issues/TODO:
---------------------
- Code format
- TX offload
- Jumbo packet send
- LRO rx
- Dynamic packet template - slow but flexible
- Test suit with summary
- mbuf packet type in scapy?
- dpdk wrapper for python - due to complexity to expand testpmd CLI, how about manipulating DPDK in python unit test framework?

Design consideration:
---------------------------
- Syntax flexibility from Scapy
- Speed of DPDK
- Quick batch regression for developer to avoid anything broken
