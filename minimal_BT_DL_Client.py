from bencodepy import * # bencoding library. If this isn't found by default,
# install it with 'pip install bencodepy'
from socket import *
from bitarray import bitarray
import requests     # http requests
import hashlib      # SHA1 hashing for info hash
import binascii     # use unhexlify to convert ascii hex sequences into binary
import random       # create the local peer id
import math         # you'll need to use the ceil function in a few places
import sys
import re
from string import ascii_letters, digits

ALPHANUM    = ascii_letters + digits
INTERESTED  = b'\x00\x00\x00\x01\x02'


# Here are some global variables for your use throughout the program.
local_port          = 62690
peer_id             = ('M0-0-1-' +  ''.join(random.sample(ALPHANUM, 13)))
protocol_string     = 'BitTorrent protocol'
reserved_hex_ascii  = '0000000000000000' # The reserved sequence for your handshake
peer_connections    = [] # An array of PeerConnection objects
total_length        = 0 # Total length of the file being downlaoded
no_of_pieces        = 0 # Number of pieces the file's divided into
piece_length        = 0 # Size of each piece
i_have              = None # A bitarray representing which pieces we have
file_array          = [] # An array of pieces (binary sequences)
req_block_size_int  = 16384 # Recommended size for requesting blocks of data
req_block_size_hex  = int(req_block_size_int).to_bytes(4, byteorder='big', signed=True)
last_block_size_int = None # The size of the last block of the file
output_filename     = None # The name of the file we'll write to the filesystem
total_bytes_gotten  = 0 # Total number of bytes received towards the full file so far
done                = False # Are we done yet?


def main():
    global done
    # print('main working')
    # if (len(sys.argv) < 2):
    #     print('input a command line argument to represent the torrent file')

    bt_data     = get_data_from_torrent(sys.argv[1])
    info_hash   = get_info_hash(bt_data)
    tracker_req(bt_data, info_hash)

    for p in peer_connections:
        if done:
            sys.exit(1)
        else:
            try:
                print("Try to handshake "+ p.ip.decode() +" "+str(p.port))
                p.handshake(info_hash)
            except:
                pass

class PeerConnection:
    """A class representing the connection to a peer"""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.have = bitarray(endian='big')

    def handshake(self, info_hash):
        # Declare any necessary globals here

        # Your handshake message will be a bytes sequence
        # <pstrlen><pstr><reserved><info_hash><peer_id>
        # https://wiki.theory.org/BitTorrentSpecification#Handshake

        # The global reserved_hex_ascii stores the reserved value, but you'll
        # need to convert it from ascii-written hex to binary data.

        print("Trying to connect to {0}:{1}".format(self.ip.decode(), self.port))

        # You'll need to set up a TCP socket here to the peer (the self value
        # for this object represents the peer connection, remember)

        try:
            # connect to the peer and send the handshake.
        except OSError as err:
            print(err)

        # Here you'll need to consume the response. Use recv on this socket to
        # get the message. First you need to discover how big the message is
        # going to be, and then you need to consume the full handshake.

        return_handshake = #

        if return_handshake:
            print("Received handshake")
            # If you got a handshake, it's time to handle incoming messages.
        else:
            print("No returned handshake from peer")

    def handle_messages(self, sock):
        # This method will handle messages from the peer coming
        # in on the socket. Read the section of the BT specification
        # closely! Read until the "Algorithms" section.
        # https://wiki.theory.org/BitTorrentSpecification#Peer_wire_protocol_.28TCP.29

        # Declare any necessary global variables
        # here using the 'global' keyword

        while True:
            # Grab first four bytes of the message to see how
            # long the message is going to be. You can tell a lot (most of
            # what you need to know) just by the length of the message.

            # Remember, the argument to recv() tells the socket how many bytes
            # to read. Use this to control the incoming message flow.

            data =

            # Remember, the data coming in is in bytes. You'll need to get an
            # int value to determine the size of the message. Use
            #
            # int.from_bytes(data, byteorder='big')
            #
            # for this, where data is the 4 byte sequence you just read in. FYI,
            # the second argument here indicates that the bytes should be
            # read in the "big-endian" way, meaning most significant on the left.

            # Now to handle the different size cases:
            #
            if #SIZE IS BITFIELD SIZE (in bytes, of course)
                # In this case, the peer is sending us a message composed of a series
                # of *bits* corresponding to which *pieces* of the file it has. So, the
                # length of this will be... bits, bytes, pieces, oh dear! Remember there's
                # always an extra byte corresponding to the message type, which comes
                # right after the length sequence and in this case should be 5.
                # Just to be sure, you should receive another byte and make sure it is
                # in fact equal to 5, before consuming the whole bitfield.
                if # Check the message type is 5, indicating bitfield
                    print("Receiving bitfield")
                    # The peer's 'have' attribute is a bitarray. You can assign
                    # that here based on what you've just consumed, using
                    # bitarray's frombytes method.
                    #
                    # https://pypi.python.org/pypi/bitarray

                    # you can use the bitarray all() method to determine
                    # if the peer has all the pieces. For this exercise,
                    # we'll keep it simple and only request pieces from
                    # peers that can provide us with the whole file. Of course
                    # in a real BT client this would defeat the purpose.

                    # If the peer does have all the pieces, now would be a good time
                    # to let them know we're interested.


            elif #
            # SIZE IS ZERO
            # It's a keep alive message. The least interesting message in the
            # world. You can handle this however you think works best for your
            # program, but you should probably handle it somehow.


            elif #
            # SIZE IS ONE
            # If the message size is one, it could be one of several simple
            # messages. The only one we definitely need to care about is unchoke,
            # so that we know whether it's okay to request pieces. The message
            # code for unchoke is 1, so make sure you consume a byte and deal with
            # that message.

            # If you do get an unchoke, then you're doing great! You've found
            # a peer out there who will give you some data. Now would be the time
            # to go pluck up your courage and make that request!

            # When making a request here, we'll go ahead and simply start with
            # the first piece at the zero index (block) and progress through in
            # order requesting from the same peer. Note: In a real implementation,
            # you would probably take a different approach. A common way to do
            # it is to look at all peers' bitfields and find the rarest piece
            # among them, then request that one first.

                request_piece(#...

            elif #
            # SIZE IS FIVE
            # It's a have. Some clients don't want so send just a bitfield, or
            # maybe not send one at all. Instead, they want to tell you index
            # by index which pieces they have. This message would include a
            # single byte for the message type (have is 4) followed by 4 bytes
            # representing an integer index corresponding to the piece the have.

            # If you get have messages for all the pieces, that also tells you
            # that the peer has the pieces you need, so now is also a good time
            # to check their have array, and if they've got all the pieces send
            # them an interested message.


            elif #
            # SIZE IS REQUESTED BLOCK SIZE OR LAST BLOCK SIZE (PLUS 9)
            # This must be a block of data. You'll have to do the bookkeeping
            # to know whether you're consuming a standard sized block (defined
            # in global variable req_block_size_int) or a smaller one for the
            # last block, because you'll need to consume the appropriate
            # number of bytes. Check the wireshark traces for why this size
            # should be "plus 9".

            # Remember, a block isn't a full piece. Here is where I'd suggest you
            # call the function that consumes the block.

                get_block(self, data, sock)

            if not data:
            # There's also the case that there's no data for the socket. You probably
            # want to handle this in some way, particularly while you're developing
            # and haven't got all the message handling fully implemented.



def get_block(peer, data, sock):
    # This is where we consume a block of data and use it to
    # build our pieces

    # Include any necessary globals

    # We need to know how big the block is going to be (we can get that
    # from 'data'. We then want to double check that the message type is
    # the appropriate value (check the specs for the "piece" message value,
    # which is what we're reading right now))

    if # the message value is correct
        # get the index and offset. Read the description of the "piece" message
        # to see how to do this.

        while # as long as the block is smaller than the expected block size
            # continue to receive data from your socket and
            # append it to the block. When the block is the size
            # you're expecting, break out of the loop.
            # You can use len() to check the size of the block.

        # You've got a block. Now add it to the piece it belongs to. I suggest
        # Making an array of pieces which can be accessed by index.

        # It may also be helpful to keep a record of how many bytes you've gotten
        # in total towards the full file.

        # He's a little report
        print("Got a block (size: {0})\tTotal so far: {1} out of {2}".format(len(block), total_bytes_gotten, total_length))

        # If you haven't fully downloaded a piece, you need to get the next block
        # within the piece. The piece index stays the same, but the offset must
        # be shifted to get a later block. This is done by adding the requested
        # block size to the previous offset.

        if # if the resulting offset is still within the same piece,
            # the same piece with the new offset

        else # if the new offset is greater than the length of the piece, you
            # must be done with that piece. Since we're just getting pieces in
            # order, you can just go ahead and request the next piece, beginning
            # with an offset of 0. (Of course, if the next index is greater than
            # or equal to the total number of pieces, you are finished downloading
            # and should write your downloaded data to a file).

            if # There's still pieces to be downloaded
                # Request the first block of the next piece.

            else:
                # Join all the elements of the downloaded pieces array using
                # .join()
                outfile = open(output_filename, 'wb')
                # Write the full content to the outfile file

                print("Download complete. Wrote file to {0}".format(output_filename))
                done = True
                sys.exit(1)

def request_piece(# You'll need access to the socket,
    # the index of the piece you're requesting, and the offset of the block
    # within the piece.

    # Declare any necessary globals here

    # The piece index and offset will need to be converted to bytes

    # Read the specs for request structure:
    # <len=0013><id=6><index><begin><length>

    # Build the request here before sending it into the socket.
    # Length is set as a global at the recommended 16384 bytes. However, the
    # request will be disregarded if there is less data to send than that
    # amount, which is likely to be the case for the final block in the file.
    # For this reason, will probably want to build the request slighly
    # differently for the final block case. Keeping track of the total number
    # of bytes you've collected can be helpful for this.

    # Send the request:
    sock.send(req)

def tracker_req(btdata, info_hash):
    # Declare any necessary globals

    # Build the params object. Read the bittorrent specs for
    # tracker querying.
    # https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
    reqParams = { #

    # use the requests library to send an HTTP GET request to
    # the tracker
    res = requests.get(# http://docs.python-requests.org/en/master/

    # The tracker responds with "text/plain" document consisting of a
    # bencoded dictionary

    # bencodepy is a library for parsing bencoded data:
    # https://github.com/eweast/BencodePy
    # read the response in and decode it with bencodepy's decode function

    # Once you've got the dictionary parsed as "tracker_data" you can
    # print out the tracker request report:
    report_tracker(tracker_data)

    # And construct an array of peer connection objects:
    for p in # the array of peers you got from the tracekr
        peer_connections.append(PeerConnection(#

def get_info_hash(btdata):
    # https://docs.python.org/3/library/hashlib.html
    # You'll need to get the info directory, re-encode it
    # into bencode, then encrypt it with SHA1 using the
    # hashlib library and generate a digest.
    return # the info hash digest

def get_data_from_torrent(arg):
    # Declare any necessary globals

    try:
        # Read about decoding from a file here:
        # https://github.com/eweast/BencodePy


        # torrent_file = open('test.torrent', 'r')
        # torrent_file_contents = torrent_file.read()
        # print('torrent file contents', torrent_file_contents)
        btdata = #

        # Do what you need to do with the torrent data.
        # You'll probably want to set some globals, such as
        # total_length, piece_length, number of pieces (you'll)
        # need to calculate that) etc. You might want to give
        # file_array its initial value here as an array of
        # empty binary sequences (b'') that can later be appended
        # to. There may be other values you want to initialize here.

        report_torrent(btdata)

    except:
        print('Failed to parse input. Usage: python btClient.py torrent_file"\ntorrent_file must be a .torrent file')
        sys.exit(2)

    return btdata

def report_torrent(btdata):
    # Nothing special here, just reporting the data from
    # the torrent. Note the Python 3 format syntax

    # Declare necessary globals
    dummy_value = "DUMMY VALUE"
    print("Announce URL: {0}".format(dummy_value)
    print("Name: {0}".format(dummy_value)
    try:
        print("Includes {0} files".format(dummy_value)
    except:
        print("Includes one file")
    print("Piece length: {0}".format(dummy_value)
    print("Piece len (bytes): {0}".format(dummy_value)
    print("Total length: {0} ({1} bytes)".format(dummy_value, dummy_value)
    print("Number of pieces: {0}".format(dummy_value)

def report_tracker(trackdata):
    for p in # peer array returned by tracker
        print ("Peer: {0} (ip addr: {1})".format(#



if __name__=="__main__":
    print('ello')
    main()
