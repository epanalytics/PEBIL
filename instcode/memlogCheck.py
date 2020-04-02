import sys

def printUsage():
    s = 'USAGE: memlogCheck.py myFile.cachesim myFile.memlog'
    print s
    exit()

def checkCMDLineArgs(argv):
    if len(argv) != 3:
        printUsage()
        exit()
    file1 = argv[1]
    file1ext = file1[-9:]
    if file1ext != ".cachesim":
        printUsage()
        exit()
    file2 = argv[2]
    file2ext = file2[-7:]
    if file2ext != ".memlog":
        printUsage()
        exit()

def scanForStart(listt):
    i = 0
    for line in listt:
        check = line[0:3]
        if check == "BLK":
            break
        i = i + 1
    return i

#def handleCachesimSysid(cachesim, pos):

#def handleMemlogSysid():

def findMemoryLine(listt,pos):
    line = listt[pos]
    i = 0
    currChar = line[i]
    while True:
        if currChar == "M":
            return pos
        if currChar == "\t"
            pos = pos + 1
            line = listt[po]
            i = 0
            currChar = line[i]
            continue
        i = i + 1
        currChar = line[i]

def handleCachesimBLK(listt, pos, blkid):
    pos = pos + 1
    retList = []
    while True:
        line = listt[pos]
        token = line[0:3]
        if token == "BLK":
            return (retList, pos)
        

#def handleMemlogBLK():

def extractBLKnumber(filee, pos):
    line = filee[pos]
    line = line[4:]
    blkNumber = ""
    for char in line:
        if char == "\t":
            break
        blkNumber += str(char)
    return str(blkNumber)

checkCMDLineArgs(sys.argv)
f1 = open(sys.argv[1], 'r')
f2 = open(sys.argv[2], 'r')
f1list = list(f1)
f2list = list(f2)
f1pos = scanForStart(f1list)
f2pos = scanForStart(f2list)
f2pos = f2pos + 3
while True:
    blk1 = extractBLKnumber(f1list, f1pos)
    blk2 = extractBLKnumber(f2list, f2pos)
    if blk1 != blk2:
        print "Error parsing input files"
        exit()
    (list1, f1pos) = handleCachesimBLK(f1list, f1pos, blk1)
    (list2, f2pos) = handleMemlogBLK(f2list, f2pos, blk1)
    if len(list1) != len(list2):
        print "Mismatch in number of sysid's"
        exit()
    for i in range(len(list1)):
        (sysid1, read1, write1) = list1[i]
        (sysid2, read2, write2) = list2[i]
        if sysid1 != sysid2:
            print "Mismatched sysids"
            exit()
        if (read1 != read2) or (write1 != write2):
            print "Sysid: " + sysid1
            print "Cachsim reads: " + read1 + " writes: " + write1
            print "Memlog reads: " + read2 + " writes: " + write2
            exit()
    break
print "All Blk by sysid by read/writes/total operations line up between cachsim file and mem log file"
