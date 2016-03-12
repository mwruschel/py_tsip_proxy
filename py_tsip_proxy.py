#!/usr/bin/python

# py_tsip_proxy  - A simple proxy for the Trimble Standard Interface Protocol
#     (c) 2016 Christian Vogel <vogelchr@vogel.cx>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import serial
import serial.aio
import argparse
import socket
import asyncio
import binascii

DLE = 0x10
bDLE = b'\020' # DLE as bytes

ETX = 0x03
bETX = b'\003'

class TSIP_Proxy_Mgr :
	def __init__(self) :
		self.devices = set() # store Protocol instances
		self.clients = set()

	def add_conn(self, who) :
		if who.is_client :
			self.clients.add(who)
		else :
			self.devices.add(who)

		print('After add_conn(',who.peer,'):')
		print('Devices:', [ x.peer for x in self.devices ])
		print('Clients:', [ x.peer for x in self.clients ])

	def remove_conn(self, who) :
		if who in self.clients :
			self.clients.remove(who)
		if who in self.devices :
			self.devices.remove(who)

		print('After remove_conn(',who.peer,'):')
		print('Devices:', [ x.peer for x in self.devices ])
		print('Clients:', [ x.peer for x in self.clients ])

	def proto_factory(self, is_client) :
		tmp = [self, is_client]
		def generate_client() :
			return TSIP_Protocol(manager=tmp[0], is_client=tmp[1])
		return generate_client

	def packet_received(self, who, pkg) :
		l = len(pkg)
		if l > 32 :
			msg = str(binascii.hexlify(pkg[0:30]),'ascii')+' ...'
		else :
			msg = str(binascii.hexlify(pkg),'ascii')

		if who in self.devices :
			col='\033[33m'
		else :
			col='\033[34m'
		print('%s<<%s %s\033[0m'%(col, who.peer, msg))

		if who in self.devices :
			for clt in self.clients :
				clt.send_packet(pkg)
		else :
			for dev in self.devices :
				dev.send_packet(pkg)

class TSIP_Protocol(asyncio.Protocol) :
	def __init__(self, *args,manager=None, is_client=None, **kwargs) :
		self.is_client=is_client
		self.manager=manager
		super().__init__(*args, **kwargs)

	# get a nice name from the transport, also add Clt= or Dev= in front...
	def get_name_from_transport(self) :
		if type(self.transport) is serial.aio.SerialTransport :
			peer = self.transport.serial.port
		else :
			host,port = self.transport.get_extra_info('peername')
			peer = 'TCP:%s:%d'%(host, port)

		if self.is_client :
			return 'Clt='+peer
		return 'Dev='+peer

	def connection_made(self, transport) :
		self.transport = transport
		self.peer = self.get_name_from_transport()

		# for the receiving data state machine...
		self.got_dle = False
		self.buf = bytearray(1024)
		self.writep = 0

		self.manager.add_conn(self)


	def connection_lost(self, exc) :
		print('Port closed:', self.peer)
		self.manager.remove_conn(self)

	def data_received(self, data) :
		# <DLE> <ID> ...payload... <DLE> <ETX>
		# <DLE> in payload is excaped by adding a second <DLE>
		for c in data :
			if self.got_dle :
				self.got_dle = False

				if c == ETX :  # DLE+ETX -> end of packet
					self.manager.packet_received(self, self.buf[0:self.writep])
					self.writep = 0
					continue

				# now it's either escaped DLE or new packet. if it's not
				# escaped DLE but we already have some packet data queued,
				# it's actually a framing error, for now we just set the
				# write pointer to 0 to throw away data...
				if c != DLE and self.writep :
					self.writep = 0
			else :
				if c == DLE :  # may be escaped DLE in payload, new or end of packet
					self.got_dle = True
					continue
			self.buf[self.writep] = c
			if self.writep < len(self.buf)-1 :
				self.writep += 1

	def send_packet(self, pkt) :
		# calculate space needed...
		l = len(pkt)         # payload size
		l += pkt.count(bDLE) # escape DLEs
		buf = bytearray(l+3) # add DLE ... DLE ETX around payload

		# packet header = DLE
		buf[0] = DLE
		j=1

		# escape all DLEs in payload
		for c in pkt :
			if c == DLE :      # escape DLE by doubling...
				buf[j] = DLE
				j += 1
			buf[j] = c
			j += 1

		buf[j] = DLE           # end packet with DLE ETX
		buf[j+1] = ETX
		j += 2

		self.transport.write(buf)


def main() :
	parser = argparse.ArgumentParser()

	# serial
	parser.add_argument('-l', '--serial_line', metavar='DEVICE',
		type=str, dest='serial_line', default='/dev/ttyUSB0',
		help='Device to open, default /dev/ttyUSB0')
	parser.add_argument('-b', '--serial_baud', metavar='BPS',
		type=int, dest='serial_baud', default=9600,
		help='Serial port speed in bits per second.')

	# tcp
	parser.add_argument('-t', '--tcp-host', metavar='HOST',
		type=str, dest='tcp_host', default=None,
		help='Hostname to connect to (via TCP, overrides serial)')
	parser.add_argument('-p', '--tcp-port', metavar='PORT',
		type=int, dest='tcp_port', default=4001,
		help='Port number for outbound tcp-connection.')

	# server
	parser.add_argument('-s', '--server-port', metavar='PORT',
		type=int, dest='server_port', default=4001,
		help='Port number for inbound tcp-connection.')

	manager = TSIP_Proxy_Mgr()

	args = parser.parse_args()
	loop = asyncio.get_event_loop()

	if args.tcp_host :
		future = loop.create_connection(manager.proto_factory(is_client=False),
			args.tcp_host, args.tcp_port)
	else :
		future = serial.aio.create_serial_connection(loop,
			manager.proto_factory(is_client=False),
			port=args.serial_line, baudrate=args.serial_baud,
			xonxoff=False, rtscts=False, timeout=0)
	loop.run_until_complete(future)

	future = loop.create_server(manager.proto_factory(is_client=True),
		port=args.server_port)
	loop.run_until_complete(future)


	try :
		loop.run_forever()
	except KeyboardInterrupt :
		print('Ctrl-C -> exiting.')
	finally :
		loop.close()


if __name__ == '__main__' :
	main()
