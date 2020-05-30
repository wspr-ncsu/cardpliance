from __future__ import print_function
import sys
import glob
import re
import os

from lxml import etree


def process_file(path): 
    root = etree.parse(path)
    flag = False
    ids = list()
    for node in root.iter("*"): 
        if len(node) == 0: 
            # Its a leaf
            android_id = node.get("id")
            if android_id not in ids:
                ids.append(android_id)
            hint = node.get("hint")
            text = node.get("text")
            if hint:
                if "card" in hint.lower():
                    flag = True
                if "credit" in hint.lower():
                    flag = True
            if text:
                if "card" in text.lower():
                    flag = True
                if "credit" in text.lower():
                    flag = True

    print (path)
    print(flag)
    if flag:
        m = re.sub("[A-Z,_]*/uirefdata/", "", path)
        s = re.sub("/.*", "", m)
        outputPath = "ID/MASK/" + s + ".txt"
        f = open(outputPath, "a")
        for i in ids:
            if i == "-1":
                continue
            if i in open(outputPath).read():
                continue
            f.write(i + "\n")






def main(args): 
    if len(args) != 1: 
        print("Usage: ./UIRefIDExtractor.py [UIREF_DATA_PATH]")
        sys.exit(1)

    glob_pattern = "%s/*/*/layouts/*.xml" % args[0]

    for file in glob.glob(glob_pattern):
        process_file(file)

if __name__ == "__main__": 
    main(sys.argv[1:])
