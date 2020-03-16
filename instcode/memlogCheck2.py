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

def tokenizeLine(line):
    tokens = line.split("\t")
    tokens.remove("")
    return tokens

#def handleCachesimSysid(cachesim, pos):

#def handleMemlogSysid():

def findMemoryLine(listt,pos):
    line = listt[pos]

def handleCachesimBLK(listt, pos, blkid):
    retList = []
    while True: #loop through sysids
        pos = pos + 1
        line = listt[pos]
        tokens = tokenizeLine(line)
        if tokens[0] == "BLK":
            return (retList, pos)
        if tokens[1] != "M":
            continue
        retList.append((tokens[0],tokens[4],tokens[5]))
    print "Failed to return properl in handleCachesimBLK"
    exit()

def handleMemlogBLK(listt, pos, blkid):
    retList = []
    line = listt[pos+1]
    tokens = tokenizeLine(line)
    curSysid = tokens[1]
    readCount = 0
    writeCount = 0
    while True:
        pos = post + 1
        line = listt[pos]
        #TODO continue working here

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
while True: #loop over blks
    if f1pos == len(f1list):
        if f2pos == len(f2list):#we are all done
            break
        else:
            print "reached end of file 1 before of file 2"
            exit()
    elif f2pos == len(f2list):
        print "reached end of file 2 before end of file 1"
        exit()
    blk1 = extractBLKnumber(f1list, f1pos)
    blk2 = extractBLKnumber(f2list, f2pos)
    if blk1 != blk2: #make sure we are parsing the same blk
        print "Error parsing input files"
        exit()
    (list1, f1pos) = handleCachesimBLK(f1list, f1pos, blk1) 
    #f1pos gets updated to where it will be next
    (list2, f2pos) = handleMemlogBLK(f2list, f2pos, blk1)
    #f2pos gets updated to where it will be next
    if len(list1) != len(list2): #make sure they have the same number of sysids
        print "Mismatch in number of sysid's"
        exit()
    for i in range(len(list1)):
        (sysid1, read1, write1) = list1[i]
        (sysid2, read2, write2) = list2[i]
        if sysid1 != sysid2: #make sure sysids are in the same order
            print "Mismatched sysids"
            exit()
        if (read1 != read2) or (write1 != write2): #if not a match in read or writes print info
            print "Sysid: " + sysid1
            print "Cachsim reads: " + read1 + " writes: " + write1
            print "Memlog reads: " + read2 + " writes: " + write2
            exit() #then exit out early
print "All Blk by sysid by read/writes/total operations line up between cachsim file and mem log file"
