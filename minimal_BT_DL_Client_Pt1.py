# from bencodepy import * # bencoding library. If this isn't found by default,
# install it with 'pip install bencodepy'
import bencodepy
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
torrent_url         = ''


def main():
    global done
    if (len(sys.argv)==2):
        bt_data     = get_data_from_torrent(sys.argv[1])
    #     info_hash   = get_info_hash(bt_data)
    #     tracker_req(bt_data, info_hash)
    # else:
    #     print('incorrect number of arguments')


class PeerConnection:
    """A class representing the connection to a peer"""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

def tracker_req(btdata, info_hash):
    # Declare any necessary globals

    # Build the params object. Read the bittorrent specs for
    # tracker querying.
    # The parameters are then added to this URL, using standard CGI methods (i.e. a '?' after the announce URL, followed by 'param=value' sequences separated by '&').
    # https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
    reqParams = {} #

    # use the requests library to send an HTTP GET request to
    # the tracker
    # res = requests.get('http://mononoke.io')# http://docs.python-requests.org/en/master/
    # response = requests.get('https://www.instagram.com/codinblog/')
    response = requests.get('http://www.something.com')

    print('response text :', response.text)
    print('response :', dir(response))
    print('response content :', response.content)

    # ben_decoded_response_content = bencodepy.decode(response.content)
    # print(ben_decoded_response_content)

    # The tracker responds with "text/plain" document consisting of a
    # bencoded dictionary

    # bencodepy is a library for parsing bencoded data:
    # https://github.com/eweast/BencodePy
    # read the response in and decode it with bencodepy's decode function

    # Once you've got the dictionary parsed as "tracker_data" you can
    # print out the tracker request report:
    report_tracker(tracker_data)

    # And construct an array of peer connection objects:
    # for p in # the array of peers you got from the tracekr
    #     peer_connections.append(PeerConnection(#

def get_info_hash(btdata):
    # https://docs.python.org/3/library/hashlib.html
    # print('get_info_hash() btdata : ', btdata)
    # for x in btdata:
    #     print(x)

    # You'll need to get the info directory, re-encode it
    # into bencode, then encrypt it with SHA1 using the
    # hashlib library and generate a digest.
    return # the info hash digest

def get_data_from_torrent(arg):
    # Declare any necessary globals

    try:
        # Read about decoding from a file here:
        # https://github.com/eweast/BencodePy

        # file_path = arg
        file_path = arg

        # call the decode_from_file() function that's a member of the bencodepy class`
        btdata = bencodepy.decode_from_file(file_path)

        # next, build the decoded dictionary through a series of iterative statements within the btdata OrderedDict object
        # the "builder" variable used for this we'll call decoded_dict
        decoded_dict = {}

        # for each of the key:value pairs in the OrderedDict, try to decode both the key and the value
        # finally, append the results to the builder dictionary : decoded_dict
        for x,y in btdata.items():
            # print(x,y)
            x = x.decode('UTF-8')
            try:
                y = y.decode('UTF-8')
            except AttributeError:
                pass
            decoded_dict[x] = y


        # decode the array elements that exist as the value for the 'url-list' key in the decoded_dict
        for x, member in enumerate(decoded_dict['url-list']):
            decoded_dict['url-list'][x] = decoded_dict['url-list'][x].decode('UTF-8')
            # XXX test print XXX
            # print(decoded_dict['url-list'][x])

        # decode the array elements that exist as the value for the 'announce-list' key in the decoded_dict
        # this has another layer of complexity compared to decoding the elements in the 'url-list', this is
        # because some of the elements of the decoded_dict['announce-list'] are arrays themselves, need a nested loop :
        for x, member in enumerate(decoded_dict['announce-list']):
            for y, member in enumerate(decoded_dict['announce-list'][x]):
                decoded_dict['announce-list'][x][y] = decoded_dict['announce-list'][x][y].decode('UTF-8')
                # XXX test print XXX
                # print(decoded_dict['announce-list'][x][y])

        # decode the (sub)ordered-dictionary that exists as a value corresponding to the 'info' key inside the decoded_dict dictionary
        # access this (sub)ordered-dictionary with : decoded_dict['info']
        # use the appendage_dict={} in order to temporarily store the sub-ordered-dictionary, this will be appended to the decoded_dict at the correct 'info' key after traversal
        appendage_dict = {}
        for x, y in decoded_dict['info'].items():
            x = x.decode('UTF-8')
            try:
                # we don't want to decode the value at the pieces key... this is a byte string
                if x != 'pieces':
                    y = y.decode('UTF-8')
            except AttributeError:
                pass
            # append the key:value pair to the dictionary
            appendage_dict[x] = y

        # append the appendage_dict to the 'info' key of the decoded_dict dictionary, the same place where it came encoded from
        decoded_dict['info'] = appendage_dict

        # XXX test print XXX
        print(decoded_dict)

        # Do what you need to do with the torrent data.
        # You'll probably want to set some globals, such as
        # total_length, piece_length, number of pieces (you'll)
        # need to calculate that) etc. You might want to give
        # file_array its initial value here as an array of
        # empty binary sequences (b'') that can later be appended
        # to. There may be other values you want to initialize here.

        total_length = decoded_dict['info']['length']
        piece_length = decoded_dict['info']['piece length']
        number_of_pieces = total_length/piece_length
        # print('\n\ntotal length : ', total_length)
        print('total length : ', total_length)
        print('piece length : ', piece_length)
        print('number of pieces :', number_of_pieces)
        # piece_length = decoded_dict['info'].piece_length
        # number_of_pieces = total_length/piece_length

        # piece_length = 1
        # number_of_pieces = total_length/piece_length

        # report_torrent(btdata)

    except:
        print('Failed to parse input. Usage: python btClient.py torrent_file"\ntorrent_file must be a .torrent file')
        sys.exit(2)

    return btdata

def report_torrent(btdata):
    # Nothing special here, just reporting the data from
    # the torrent. Note the Python 3 format syntax

    # Declare necessary globals
    dummy_value = "DUMMY VALUE"
    print("Announce URL: {0}".format(dummy_value))
    print("Name: {0}".format(dummy_value))
    try:
        print("Includes {0} files".format(dummy_value))
    except:
        print("Includes one file")
    print("Piece length: {0}".format(dummy_value))
    print("Piece len (bytes): {0}".format(dummy_value))
    print("Total length: {0} ({1} bytes)".format(dummy_value, dummy_value))
    print("Number of pieces: {0}".format(dummy_value))

def report_tracker(trackdata):
    print('something')
#     # for p in # peer array returned by tracker
#     #     print ("Peer: {0} (ip addr: {1})".format(#
if __name__=="__main__":
    main()
