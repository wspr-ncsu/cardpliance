from __future__ import print_function
import sys
import glob
import re
import os

from lxml import etree

# LayoutDump => DFS to get to a View, then dump the ID IF privacyTag = credit_card_info

def process_file(path): 
    root = etree.parse(path)
    for node in root.iter("*"): 
        if len(node) == 0: 
            # Its a leaf
            tag = node.get("privacyTag")
            if tag and tag == "credit_card_security_code": 
                # Has an annotation
                android_id = node.get("id")
                #print(path + " " +android_id)
                m= re.sub("[A-Z,_]*/uirefdata/","",path)
                s= re.sub("/.*","",m)
                outputPath = "ID/CVC/"+s+".txt"
                f = open(outputPath,"a")
                f.write(android_id+"\n")

def main(args): 
    if len(args) != 1: 
        print("Usage: ./UIRefIDExtractor.py [UIREF_DATA_PATH]")
        sys.exit(1)

    glob_pattern = "%s/*/*/layouts/*.xml" % args[0]

    for file in glob.glob(glob_pattern):
        process_file(file)

if __name__ == "__main__": 
    main(sys.argv[1:])
