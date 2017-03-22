import sys, os
from bencodepy import *

decoded_file = decode_from_file('test.torrent')
print(decoded_file)
