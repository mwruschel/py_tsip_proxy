#!/usr/bin/python
from collections import namedtuple
import binascii
import asyncio
import struct
import logging
import datetime
import math
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

Pkt_Raw_Data_Measurement_Data = namedtuple('Raw_Data_Measurement_Data', [
        'sv_prn', 'sample_length', 'signal_level', 'code_phase',
        'doppler', 'time_of_measurement'
    ])

Pkt_Satellite_Tracking_Status = namedtuple('Satellite_Tracking_Status', [
        'sv_prn',               # B  # 1-31
        'slot_and_ch_number',   # B  7-3=ch, 2-0=slot (unused)
        'acquisition_flat',     # B  0: never acq., 1: acq., 2: reopened search
        'ephemeris_flag',       # B  0: flag not set, >0: good ephemeris
        'signal_level',             # f AMU
        'time_of_last_measurement', # f sec
        'elevation',                # f radians
        'azimuth',                  # f radians
        'old_measurement_flag',     # B 0: not seg >0: measurement old
        'integer_msec_flag',        # B 0: unknown, 1: subframe, 2: bitcrossing,
                                    #     3: verified, 4: suspect error
        'bad_data_flag',            # B 0: flag unset, 1: bad parity, 2: bad ephemeris
        'data_collection_flag',     # B 0: unset, 1: collection in progress
    ])

SIMPLE_PACKETS = {
    # Thunderbolt-2012-02.pdf, Appendix A, Page 79
    '8f-ab': ( '>xIHhBBBBBBH',           Pkt_Primary_Timing      ),
    # Thunderbolt-2012-02.pdf, Appendix A, Page 82
    '8f-ac': ( '>xBBBIHHBBBBffIffdddfI', Pkt_Supplemental_Timing ),
    # Thunderbolt-2012-02.pdf, Appendix A, Page 56
    '5a':    ( '>Bffffd',                Pkt_Raw_Data_Measurement_Data ),
    # Thunderbolt-2012-02.pdf, Appendix A, Page 57
    '5c':    ( '>BBBBffffBBBB',          Pkt_Satellite_Tracking_Status ),
}

class TSIP_Protocol(asyncio.Protocol) :
    def __init__(self) :
        self.name = 'undef'
        self.transport = None
        self.state = self._idle
        self.buf = bytearray()
        self.do_debug = (logging.getLogger().level == logging.DEBUG)
        self.junk = 0

    # state handlers --------------------------------------------------------
    def _idle(self, c) :
        if c == DLE :
            if self.junk :
                warning('%s %d junk bytes received waiting for DLE.',
                    self.name, self.junk)
                self.junk = 0
            self.buf.clear()
            return self._data

        self.junk += 1
        if self.do_debug :
            debug('%s junk byte 0x%02x'%(self.name, c))

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

    # packet received -------------------------------------------------------
    def _packet_recved(self, pkt) :
        if self.do_debug :
            if len(pkt) >= 2 :
                pkt_name = '%02x-%02x'%(pkt[0], pkt[1])
            elif len(pkt) == 1 :
                pkt_name = '%02x'%(pkt[0])
            else :
                pkt_name = 'empty'

            if len(pkt) < 11 :
                pkt_str = binascii.hexlify(pkt).decode('ascii')
            else :
                pkt_str = binascii.hexlify(pkt[:10]).decode('ascii') + '..'
            debug('%s << %-5s (%02d) %s'%(self.name, pkt_name, len(pkt), pkt_str))
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
            self.name = 'Master %-21s'%(myname)
        elif self.__class__ == TSIP_Protocol_Slave :
            self.name = 'Slave  %-21s'%(myname)
        else :
            self.name = 'TSIP   %-21s'%(myname)

        info('%s Connection made.',self.name)

    def connection_lost(self, exc) :
        info('%s Connection lost: %s',self.name, str(exc))

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

class TSIP_Logger :
    def __init__(self, logfile_basename, master, do_flush=False) :
        self.master = master
        self.name = 'Logger'
        self.do_flush = do_flush
        self.logfile_basename = logfile_basename

        ###
        # logfile filehandle and name
        ###
        self.f = None
        self.fn = None

        ###
        # remember last primary timing information, we dump on reception
        # of supplemental timing
        ###
        self.primary_timing = None

        ###
        # accumulate sat info, also remember last time when satinfo
        # has been received, so that we can request an update from the receiver
        ###
        self.satinfo = dict()
        self.sattrack = dict()
        self.last_satinfo = datetime.datetime.now()

        self.master.register_slave(self)

    # decoding --------------------------------------------------------------
    def decode_simple(self, msgid, payload) :
        if len(payload) >= 1 :
            pkt_id = '%02x-%02x'%(msgid, payload[0])
            simple_decoder = SIMPLE_PACKETS.get(pkt_id)
        if not simple_decoder :
            pkt_id = '%02x'%(msgid)
            simple_decoder = SIMPLE_PACKETS.get(pkt_id)
        if not simple_decoder :
            return None, payload

        fmt, nt = simple_decoder
        expect_len = struct.calcsize(fmt)
        if expect_len != len(payload) :
            warning('Cannot decode %s, need %d bytes, but got %d.'%(pkt_id,
                expect_len, len(payload)))
            return None, payload
        return pkt_id, nt(*struct.unpack(fmt, payload))

    def process_packet(self, pkt) :
        if len(pkt) == 0 :
            return
        pkt_id, data = self.decode_simple(pkt[0], pkt[1:])
        if pkt_id is None :
            return

        if type(data) is Pkt_Primary_Timing :
            self.primary_timing = data
            return

        now = datetime.datetime.now()

        if type(data) is Pkt_Raw_Data_Measurement_Data :
            self.last_satinfo = now
            self.satinfo[data.sv_prn] = data
            return

        if type(data) is Pkt_Satellite_Tracking_Status :
            self.last_satinfo = now
            self.sattrack[data.sv_prn] = data
            return

        # we only continue when we have primary and suppmental timing information
        if type(data) is not Pkt_Supplemental_Timing or self.primary_timing is None:
            return

        ###
        # check whether we need to request new sat info
        ###
        dt_satinfo = now - self.last_satinfo
        if dt_satinfo.total_seconds() > 10 :
            self.last_satinfo = now
            # Command Packet 0x3A: Request Last Raw Measurement
            # Byte 0: Satellite PRN (1-31, or 0 for all)
            debug('%s Send 0x3A: Request Last Raw Measurement', self.name)
            self.master.send_packet(b'\x3a\x00')
            # Command Packet 0x3C: Request Satellite Tracking Status
            self.master.send_packet(b'\x3c\x00')

        ###
        # we have a "primary timing" dataset stored, and this packet
        # is a "supplemental timing" packet -> write out to logfile
        ###
        new_fn = self.logfile_basename + now.strftime('_%Y%m%d.txt')
        if not self.f or (new_fn != self.fn) :
            if self.f :
                info('%s: closing old logfile.'%(self.name))
                self.f.close()
            self.fn = new_fn
            self.f = open(new_fn,'at')
            info('%s: appending to logfile %s.'%(self.name, self.fn))

        #    tstamp  tow  week flags rm dm critic minor decstat da pps    dac    temp
        fmt='%-15.3f %6d %4d 0x%02x %d %d 0x%04x 0x%04x 0x%02x %d %+6.3f %+8.5f %6.3f'
        p = self.primary_timing
        s = data # supplemental
        print(fmt%(
            now.timestamp(),
            p.time_of_week, p.week_number, p.timing_flags,
            s.receiver_mode, s.disciplining_mode, s.critical_alarms,
            s.minor_alarms, s.gpsdecoding_status, s.disciplining_activity,
            s.pps_offset, s.dac_voltage, s.temperature
        ), file=self.f)

        for prn in set(self.satinfo).union(self.sattrack) :
            satinfo = self.satinfo.get(prn)
            track = self.sattrack.get(prn)
            print('# SAT %02d'%(prn), file=self.f, end='')

            if satinfo :
                print(' %5.2f %7.1f %7.1f'%(
                    satinfo.signal_level, satinfo.code_phase, satinfo.doppler),
                    file=self.f, end='')
            else :
                print('     -       -       -', file=self.f, end='')

            if track :
                print(' %5.2f %5.1f %5.1f'%(
                    track.signal_level,
                    track.azimuth*(180./math.pi),
                    track.elevation*(180./math.pi)), file=self.f)
            else :
                print('     -     -     -', file=self.f)

        if self.do_flush :
            self.f.flush()

        self.satinfo.clear()
        self.sattrack.clear()

    send_packet = process_packet


def main() :
    import argparse
    import logging

    parser = argparse.ArgumentParser(description='''
py_tsip_proxy is a proxy for the Trimble Standard Interface Protocol
(TSIP). It allows several clients to connect to one single TSIP capable
device. Assuming the TSIP capable device is a GPS controlled clock (e.g.
timing standard, GPSDO (GPS disciplined oscillator), a logfile can be
written to disk for monitoring purposes.

This software lives at https://github.com/vogelchr/py_tsip_proxy and has
been tested with a Trimbe Thunderbolt http://www.leapsecond.com/tbolt-faq.htm.
''')

    parser.add_argument('-d', '--debug', action='store_true', default=False,
            help='''Write packets sent/received by each client. (def: don't)''')

    grp = parser.add_argument_group('Serial or Network Connection to GPS Device')

    grp.add_argument('-t', '--tcp', metavar='PORT', dest='tcp_port',
        type=int, action='store', default=None,
        help='Use TCP connection and specify port number. (def: use serial)')

    grp.add_argument('-b', '--baud', dest='baud',
        type=int, action='store', default=9600,
        help='Baudrate to use on serial device (def: 9600)')

    grp.add_argument('tty_or_host', metavar='TTY|HOST',
        type=str, action='store', default=None,
        help='Serial device or hostname when using TCP connection.')

    grp = parser.add_argument_group('Listening Sockets')

    grp.add_argument('-l', '--listen', dest='listen',
        type=int, action='store', default=4321, metavar='PORT',
        help='''Listen for local connections on tcp port whose
packets will be forwarded to the device (def: 4321).''')

    grp.add_argument('-m', '--listen-mute', dest='listen_mute',
        type=int, action='store', default=None, metavar='PORT',
        help='''Listen for local connections on tcp port whose
packets will not be forwarded to the device (def: None).''')

    grp = parser.add_argument_group('Logging to ASCII Files')

    grp.add_argument('-o', '--logfile', dest='logfile',
        type=str, action='store', default=None, metavar='BASE',
        help='''Write GPS stats (primary and supplemental timing
        information and GPS satellite data) to logfile, files will be
        named BASE_YYYYmmdd.txt and reopened at midnight local time.
        (def: no logfile)''')

    grp.add_argument('-f', '--flush', action='store_true',
            default=False, help='''Flush logfiles after each line. Useful
            if you are watching with "tail -f", but wears out storage
            faster as the file will fsync() after every single line. (def:
            no flush)''')

    args = parser.parse_args()

    logging.basicConfig(
        format='%(asctime)-15s %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

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

    if args.logfile :
        logger = TSIP_Logger(args.logfile, protocol_master, args.flush)

    loop.run_forever()

if __name__ == '__main__' :
    main()
