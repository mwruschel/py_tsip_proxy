#!/usr/bin/python
from collections import namedtuple
import binascii
import asyncio
import struct
import logging
from logging import debug, info, warning, error, critical

# https://pypi.python.org/pypi/pyserial-asyncio
import serial_asyncio

###
# Trimble Standard Interface Protocol
###
DLE = 0x10
ETX = 0x03

Pkt_Primary_Timing = namedtuple('Primary_Timing',[
        'time_of_week', 'week_number', 'utc_offset',
        'timing_flags', 'seconds', 'minutes', 'hours',
        'day_of_month', 'month', 'year'])

Pkt_Supplemental_Timing = namedtuple('Supplemental_Timing', [
    'receiver_mode', 'disciplining_mode', 'selfsurvey_progress',
    'holdover_duration', 'critical_alarms', 'minor_alarms',
    'gpsdecoding_status', 'disciplining_activity', 'spare_status1',
    'spare_status2', 'pps_offset', 'clock_offset', 'dac_value',
    'dac_voltage', 'temperature', 'latitude', 'longitude', 'altitude',
    'pps_quantization_error', 'spare'])

simple_packets = {
    # Thunderbolt-2012-02.pdf, Appendix A, Page 79
    '8f-ab': ( '>xIHhBBBBBBH', Pkt_Primary_Timing ),
    # Thunderbolt-2012-02.pdf, Appendix A, Page 82
    '8f-ac': ( '>xBBBIHHBBBBffIffdddfI', Pkt_Supplemental_Timing )
}

class TSIP_Protocol(asyncio.Protocol) :
    def __init__(self) :
        self.name = 'undef'
        self.transport = None
        self.state = self._idle
        self.buf = bytearray()

    # state handlers --------------------------------------------------------
    def _idle(self, c) :
        if c == DLE :
            self.buf.clear()
            return self._data
        warning('%s received junk byte %02x', self.name, c)

    def _data(self, c) :
        if c == DLE :
            return self._dle_recv
        self.buf.append(c)

    def _dle_recv(self, c) :
        # <DLE> <DLE> : escaped <DLE> inside packet
        if c == DLE :
            self.buf.append(c)
            return self._data
        # <DLE> <ETX> : end of packet
        if c == ETX :
            self._packet_recved(bytes(self.buf))
            return self._idle
        # state probably messed up and this is the ID of a new packet
        warning('%s received stray DLE, assume new packet', self.name)
        self.buf.clear()
        self.buf.append(c)
        return self._data

    # decoding --------------------------------------------------------------
    def decode_simple(self, msgid, pkt, fmt, nt) :
        if struct.calcsize(fmt) != len(pkt) :
            warning('Need %d bytes, but have %d.', struct.calcsize(fmt), len(pkt))
            return None
        return nt(*struct.unpack(fmt, pkt))

    # packet received -------------------------------------------------------
    def _packet_recved(self, pkt) :
        decoded = None
        if len(pkt) >= 2 :
            name = '%02x-%02x'%(pkt[0], pkt[1])
            if name in simple_packets :
                decoded = self.decode_simple(pkt[0], pkt[1:], *simple_packets[name])
        if len(pkt) >= 1 and not decoded :
            name = '%02x'%(pkt[0])
            if name in simple_packets :
                decoded = self.decode_simple(pkt[0], pkt[1:], *simple_packets[name])
        if not decoded :
            decoded = binascii.hexlify(pkt).decode('ascii') + '(%d)'%(len(pkt))

        txt = str(decoded)
        if len(txt) > 40 :
            txt = txt[:37]+'...'
        debug('%s %s',self.name, txt)

        self.process_packet(pkt)

    def process_packet(self, pkt) :
        pass

    def send_packet(self, pkt) :
        txbuf = bytearray()
        txbuf.append(DLE)

        for c in pkt :
            if c == DLE :
                txbuf.append(DLE)
            txbuf.append(c)

        txbuf.append(DLE)
        txbuf.append(ETX)

        self.transport.write(txbuf)

    # connection management -------------------------------------------------
    def connection_made(self, transport) :
        self.transport = transport

        if type(transport) == serial_asyncio.SerialTransport :
            myname = transport.serial.port
        else :
            peer = transport.get_extra_info('peername')
            if peer is not None :
                myname = '%s/%d'%peer
            else :
                myname = '???'

        if self.__class__ == TSIP_Protocol_Master :
            self.name = 'Master %s'%(myname)
        elif self.__class__ == TSIP_Protocol_Slave :
            self.name = 'Slave %s'%(myname)
        else :
            self.name = 'TSIP %s'%(myname)

        info('%s Connection made.',self.name)

    def connection_lost(self, exc) :
        info('%s Connectino lost: %s',self.name, str(exc))

    def data_received(self, data) :
        for c in data :
            ret = self.state(c)
            if ret is not None :
                self.state = ret

    def eof_received(self) :
        info('%s EOF received',self.name)

###
# a master allows clients to register and forwards packets to
# all its slaves
###
class TSIP_Protocol_Master(TSIP_Protocol) :
    def __init__(self) :
        super().__init__()
        self.slaves = set()

    def register_slave(self, slave) :
        info('%s new slave %s',self.name, slave.name)
        self.slaves.add(slave)

    def unregister_slave(self, slave) :
        info('%s removed slave %s',self.name, slave.name)
        self.slaves.remove(slave)

    def process_packet(self, pkt) :
        for slave in self.slaves :
            slave.send_packet(pkt)

###
# a slave registers with its master and forwards packets to it
#  (if forward_to_master is True)
###
class TSIP_Protocol_Slave(TSIP_Protocol) :
    def __init__(self, master, forward_to_master=False) :
        super().__init__()
        self.master = master
        self.forward_to_master = forward_to_master

    def connection_made(self, transport) :
        super().connection_made(transport)
        self.master.register_slave(self)

    def connection_lost(self, exc) :
        self.master.unregister_slave(self)
        super().connection_lost(exc)

    def process_packet(self, pkt) :
        if self.forward_to_master :
            self.master.send_packet(pkt)

def main() :
    import argparse
    import logging

    logging.basicConfig(
        format='%(asctime)-15s %(message)s',
        level=logging.INFO)

    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--tcp', metavar='PORT', dest='tcp_port',
        type=int, action='store', default=None,
        help='Use TCP connection to port.')

    parser.add_argument('-b', '--baud', dest='baud',
        type=int, action='store', default=9600,
        help='Baudrate to use on serial device (def: 9600)')

    parser.add_argument('-l', '--listen', dest='listen',
        type=int, action='store', default=4321, metavar='PORT',
        help='''Listen for local connections on tcp port whose
packets will be forwarded to the device (def: 4321).''')

    parser.add_argument('-m', '--listen-mute', dest='listen_mute',
        type=int, action='store', default=None, metavar='PORT',
        help='''Listen for local connections on tcp port whose
packets will not be forwarded to the device (def: None).''')

    parser.add_argument('tty_or_host', metavar='TTY|HOST',
        type=str, action='store', default=None,
        help='Connect to serial device or host via the network.')

    args = parser.parse_args()
    loop = asyncio.get_event_loop()

    if args.tcp_port :
        conn_future = loop.create_connection(TSIP_Protocol_Master,
                args.tty_or_host, args.tcp_port)
    else :
        conn_future = serial_asyncio.create_serial_connection(loop,
            TSIP_Protocol_Master, args.tty_or_host, baudrate=args.baud)

    transport, protocol_master = loop.run_until_complete(conn_future)
    slave = TSIP_Protocol_Slave(protocol_master)

    ###
    # listen socket
    ###
    bind_future = loop.create_server(
        lambda: TSIP_Protocol_Slave(protocol_master, True), port=args.listen)
    loop.run_until_complete(bind_future)

    if args.listen_mute :
        bind_future = loop.create_server(
            lambda: TSIP_Protocol_Slave(protocol_master, False),
            port=args.listen_mute)
        loop.run_until_complete(bind_future)

    loop.run_forever()

if __name__ == '__main__' :
    main()
