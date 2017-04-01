# XXX SOURCES :
# https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
# https://github.com/eweast/BencodePy
# https://docs.python.org/3/library/hashlib.html
# http://mathcs.pugetsound.edu/~tmullen/classes/s17-CS325-nw/

# XXX QUESTIONS — for professor mullen
# how can we determine the number of files in a given torrent based on the test.torrent meta-info?

# You state that we must manipulate the OrderedDict to produce the info_hash :
# """
# You'll need to get the info directory, re-encode it
# into bencode, then encrypt it with SHA1 using the
# hashlib library and generate a digest.
# """
# For this operation, should we take the OrderedDict containing the byte literals (notated with b'')?
    #  OR
# should we instead re-encode the decoded OrderedDictionary to to generate the info_hash?

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
import urllib


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
piece_length_bytes  = 0 
i_have              = None # A bitarray representing which pieces we have
file_array          = [] # An array of pieces (binary sequences)
req_block_size_int  = 16384 # Recommended size for requesting blocks of data
req_block_size_hex  = int(req_block_size_int).to_bytes(4, byteorder='big', signed=True)
last_block_size_int = None # The size of the last block of the file
output_filename     = None # The name of the file we'll write to the filesystem
total_bytes_gotten  = 0 # Total number of bytes received towards the full file so far
total_length_bytes  = 0
done                = False # Are we done yet?
torrent_url         = ''
announce_url        = ''
# variable used to store the global bencodepy decoded ordered dict & info
btdata_backup       = None
btdata_info_backup  = None
#listpeers = []



def main():
    global done
    if (len(sys.argv)==2):
        bt_data     = get_data_from_torrent(sys.argv[1])
        info_hash   = get_info_hash(bt_data)
        # call tracker request
        tracker_req(bt_data, info_hash)
    else:
        print('incorrect number of arguments')


# define a TorrentData object type
# the purpose of this class is to store data corresponding to the
# meta-data that's extracted from the .torrent file in an organized way
class TorrentData:
    # class constructor
    def __init__(self, output_filename, total_length, total_length_bytes, piece_length, piece_length_bytes, no_of_pieces, announce_url):
        self.output_filename = output_filename
        self.total_length = total_length
        self.total_length_bytes = total_length_bytes
        self.piece_length = piece_length
        self.piece_length_bytes = piece_length_bytes
        self.no_of_pieces = no_of_pieces
        self.announce_url = announce_url

class PeerConnection:
    """A class representing the connection to a peer"""
    def __init__(self, ip, port, pid):
        self.ip = ip
        self.port = port
        self.pid = pid
        # self.id = id

# this function is used to make a request to the remote tracker server.
# the tracer server listens for a request of a given torrent
# if the tracker has a record for the torrent,
# then the tracker will respond with a "map" of peers that have the desired
# torrent "pieces" available
# note, if parameters are sent to the script via an HTTP GET request (a question mark appended to the URL, followed by param=value pairs; in the example, ?and=a&query=string)
# example, ?and=a&query=string
def tracker_req(btdata, info_hash):

    # Declare any necessary globals
    #b'info' has the info....
    # Build the params object. Read the bittorrent specs for tracker querying
    # https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
    info = btdata['info']
    total_length_bytes = info['length']
    left = total_length_bytes - total_bytes_gotten
    reqParams = {'info_hash':info_hash, 'peer_id':peer_id, 'port':local_port, 'uploaded':0, 'downloaded':total_bytes_gotten, 'left':left, 'compact':1}

    # use the requests library to send an HTTP GET request to the tracker
    # http://docs.python-requests.org/en/master/
    print(btdata['announce'])
    res = requests.get(btdata['announce'], params=reqParams) 
    #bencodepy will decode encoded data in bytes format
    #the web server sends you ASCII
    #take that ASCII and encode it to bytes
    #call encode on the text file returned from the server. 
    # then you can decode it
    newres = res.text
    newres = newres.encode('latin-1')
    #print("\nprinting text:\n")
    #text = json.loads(res.text)
    #print(text)
    #print("\n just tried to print res.text")
    # The tracker responds with "text/plain" document consisting of a
    # bencoded dictionary
    # bencodepy is a library for parsing bencoded data:
    # https://github.com/eweast/BencodePy
    # read the response in and decode it with bencodepy's decode function
    tracker_data = bencodepy.decode(newres)
    #  XXX test print XXX
    ###print("\nprinting tracker_data:\n")
    ###print(tracker_data) #this tracker data should be a list of peers
    ###print("\nprinting tracker_data[b'interval']:\n")
    ###print(tracker_data[b'interval'])
    ###print("\nprinting tracker_data[b'peers']:\n")
    ###print(tracker_data[b'peers'])
    ###print("\nprinting btdata:\n")
    ###print(btdata)
    ###print("\nprinting info_hash:\n")
    ###print(info_hash)
    listpeers = tracker_data[b'peers']

    # Once you've got the dictionary parsed as "tracker_data" you can
    # print out the tracker request report:
    report_tracker(tracker_data)
    # And construct an array of peer connection objects:
    # for p in # the array of peers you got from the tracker
    for p in listpeers:
        peer_connections.append(p)

# the purpose of this is to produce the info_hash variable, which is requisite in the
# request for the tracker server
def get_info_hash(btdata):
    # https://docs.python.org/3/library/hashlib.html
    # get the info directory, re-encode it into bencode, then encrypt it with
    # SHA1 using the hashlib library and generate a digest.

    # XXX test print XXX
    # print("\n\n::::::btdata backup  : \n\n", btdata_backup, "\n\n")
    # print("\n\n::::::INFO btdata backup  : \n\n", btdata_info_backup, "\n\n")

    # XXX test print XXX
    # print('re-encoded : ', btdata['info'])

    # first, encode info_dictionary in bencode before encrypting using sha1
    encoded_info_dictionary = bencodepy.encode(btdata_info_backup)

    # XXX test print XXX
    ###print('encoded info dictionary : ', encoded_info_dictionary)

    # encrypt the encoded_info_dictionary using sha1 & generate sha1 hash digest
    digest_builder = hashlib.sha1()
    digest_builder.update(encoded_info_dictionary)
    digest_builder = digest_builder.digest()

    # XXX test print XXX
    # print('digest builder : , digest_builder,'\n\n')

    return digest_builder

def get_data_from_torrent(arg):
    # https://github.com/eweast/BencodePy
    # try to parse and decode the torrent file...
    try:

        # assign file_path based on the command line arg/param
        file_path = arg

        # call the decode_from_file() function that's a member of the bencodepy class`
        btdata = bencodepy.decode_from_file(file_path)

        # store the fresh, bencodepy decoded data in the global scope
        global btdata_backup
        btdata_backup = btdata
        # btdata_info_backup =

        # XXX test print XXX
        # print("\n\n::::::btdata backup  : \n\n", btdata_backup, "\n\n")

        # next, build the decoded dictionary through a series of iterative statements within the btdata OrderedDict object
        # the "builder" variable used for this we'll call decoded_dict
        decoded_dict = {}

        # for each of the key:value pairs in the OrderedDict, try to decode both the key and the value
        # finally, append the results to the builder dictionary : decoded_dict
        for x,y in btdata.items():
            # print(x,y)
            x = x.decode('UTF-8')
            # try to decode the value associated with the key...
            try:
                y = y.decode('UTF-8')
            except AttributeError:
                # if we can't decode the value, just pass it for now
                pass
            decoded_dict[x] = y

        # decode the array elements that exist as the value for the 'url-list' key in the decoded_dict
        for x, member in enumerate(decoded_dict['url-list']):
            decoded_dict['url-list'][x] = decoded_dict['url-list'][x].decode('UTF-8')

        # decode the array elements that exist as the value for the 'announce-list' key in the decoded_dict
        # this has another layer of complexity compared to decoding the elements in the 'url-list', this is
        # because some of the elements of the decoded_dict['announce-list'] are arrays themselves, need a nested loop :
        for x, member in enumerate(decoded_dict['announce-list']):
            for y, member in enumerate(decoded_dict['announce-list'][x]):
                decoded_dict['announce-list'][x][y] = decoded_dict['announce-list'][x][y].decode('UTF-8')


        # store freshly bencodepy decoded info-ordered-dictionary
        global btdata_info_backup
        btdata_info_backup = decoded_dict['info']

        # decode the (sub)ordered-dictionary that exists as a value corresponding to the 'info' key inside the decoded_dict dictionary
        # access this (sub)ordered-dictionary with : decoded_dict['info']
        # use the appendage_dict={} in order to temporarily store the sub-ordered-dictionary, this will be appended to the decoded_dict at the correct 'info' key after traversal
        appendage_dict = {}
        for x, y in decoded_dict['info'].items():
            x = x.decode('UTF-8')
            # try to decode the value associated with the key...
            try:
                # we don't want to decode the value at the pieces key... this is a byte string
                if x != 'pieces':
                    y = y.decode('UTF-8')
            except AttributeError:
                # if we can't decode the value, just pass it for now
                pass
            # append the key:value pair to the dictionary
            appendage_dict[x] = y

        # append the appendage_dict to the 'info' key of the decoded_dict dictionary, the same place where it came encoded from
        decoded_dict['info'] = appendage_dict

        # XXX test print XXX
        print(decoded_dict)
        # XXX test print XXX

        # Do what you need to do with the torrent data.
        # You'll probably want to set some globals, such as
        # total_length, piece_length, number of pieces (you'll)
        # need to calculate that) etc. You might want to give
        # file_array its initial value here as an array of
        # empty binary sequences (b'') that can later be appended
        # to. There may be other values you want to initialize here.

        # instantiate an object to have the TorrentData class type
        # assign all of the key:value pairs to correspond to the relevant bit_torrent data
        # note : the number of pieces is thus determined by 'ceil( total length / piece size )'
        torrent_data = TorrentData(\
            decoded_dict['info']['name'],\
            decoded_dict['info']['length'],\
            decoded_dict['info']['length']/8,\
            decoded_dict['info']['piece length'],\
            decoded_dict['info']['piece length']/8,\
            math.ceil(decoded_dict['info']['length']/decoded_dict['info']['piece length']),\
            decoded_dict['announce'])

        #  XXX test print XXX
        # print('total length : ', total_length)
        # print('piece length : ', piece_length)
        # print('piece length bytes : ', piece_length_bytes)
        # print('number of pieces :', no_of_pieces)
        # print('announce url :', announce_url)
        # print('output file name : ', output_filename)
        # print(decoded_dict['info']['pieces'])
        # print('type :', type(decoded_dict['info']['pieces'])) # type of
        #  XXX test print XXX

        # reporting torrent :
        report_torrent(torrent_data)

    except:
        print('Failed to parse input. Usage: python btClient.py torrent_file"\ntorrent_file must be a .torrent file')
        sys.exit(2)

    return decoded_dict


# note : i modified professor mullen's original function to accept a TorrentData-type object
# as the parameter—this is a class defined above. instead of remorting data from the global
# variables assiciated with this program, read datas that are associated with the TorrentData object
def report_torrent(torrent_data):
    # Nothing special here, just reporting the data from
    # the torrent. Note the Python 3 format syntax

    # assume that the number of files in the torrent is "one"
    no_of_files = "one"

    print("\nAnnounce URL: {0}".format(torrent_data.announce_url))
    print("Name: {0}".format(torrent_data.output_filename))
    try:
        print("Includes {0} files".format(no_of_files))
    except:
        print("Includes one file")
    print("Piece length: {0}".format(torrent_data.piece_length))
    print("Piece len (bytes): {0}".format(torrent_data.piece_length_bytes))
    print("Total length: {0} ({1} bytes)".format(torrent_data.total_length, torrent_data.total_length_bytes))
    print("Number of pieces: {0}".format(torrent_data.no_of_pieces))


def report_tracker(trackdata):
    listpeers1 = trackdata[b'peers']
    print("\n")
    for odict in listpeers1:
        for key, value in odict.items():
            dkey = key.decode('latin-1')
            if dkey=="ip":
                dIpval = value.decode('latin-1')
            elif dkey=="peer id":
                try:
                    dPidval = value.decode('latin-1')
                except:
                    pass
        print("Peer: " + dPidval + " (ip addr: " + dIpval + ")")

if __name__=="__main__":
    main()
