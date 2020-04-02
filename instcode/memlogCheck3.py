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

def tokenizeLine(line):
    line = line.rstrip("\n")
    tokens = line.split("\t")
    if tokens[0] == "":
        tokens.remove("")
    return tokens

def scanForStart(listt):
    i = 0
    for line in listt:
        check = line[0:3]
        if check == "BLK":
            break
        i = i + 1
    return i

def handleCacheSim(flist, pos, dic):
    currentBLK = ""
    while pos<len(flist):
        line = flist[pos]
        tokens = tokenizeLine(line)
        if tokens[0] == "BLK":
            currentBLK = tokens[1]
            pos = pos + 1
            continue
        if tokens[1] == "M":
            tempDict = dic.get(currentBLK)
            if tempDict == None:
                tempDict = {}
            tempDict[tokens[0]] = (tokens[4],tokens[5])
            dic[currentBLK] = tempDict
        pos = pos + 1
    return dic

def handleMemLog(flist, pos, dic):
    while pos<len(flist):
        line = flist[pos]
        tokens = tokenizeLine(line)
        if line[0] == "#":
            pos = pos + 1
            continue
        if tokens[0] == "BLK":
            pos = pos + 1
            continue
        BLK = tokens[0]
        SYS = tokens[1]
        reads = int(tokens[4])
        write = int(tokens[5])
        tempDict = dic.get(BLK)
        if tempDict == None:
            tempDict = {}
        tup = tempDict.get(SYS)
        if tup == None:
            tup = (0,0)
        curR = tup[0] + reads
        curW = tup[1] + write
        tup = (curR, curW)
        tempDict[SYS] = tup
        dic[BLK] = tempDict
        pos = pos + 1
    return dic

checkCMDLineArgs(sys.argv)
f1 = open(sys.argv[1], 'r')
f2 = open(sys.argv[2], 'r')
f1list = list(f1)
f2list = list(f2)
f1pos = scanForStart(f1list)
f2pos = scanForStart(f2list)
f2pos = f2pos + 3
cachesimdict = {}
memlogdict = {}
cachesimdict = handleCacheSim(f1list, f1pos, cachesimdict)
memlogdict = handleMemLog(f2list, f2pos, memlogdict)
print "BLK\tSYSID\tCacheRead\tMemRead\tCacheWrite\tMemWrite"
error = False
BLKS = cachesimdict.keys()
for BLK in BLKS: #cache key is BLK, level 1; cache value is DIC with SYSIDS, level 1
    sysiddic = cachesimdict.get(BLK)
    SYSIDS = sysiddic.keys()
    for SYSID in SYSIDS: #cache key, level 2; cache value, level 2
        cvalue2 = sysiddic.get(SYSID)
        mvalue1 = memlogdict.get(BLK)
        if mvalue1 == None:           
            mvalue1 = {}
        mvalue2 = mvalue1.get(SYSID)
        if mvalue2 == None:
            mvalue2 = (0,0)
        print "info: "+str(BLK)+","+str(SYSID)+","+str(cvalue2[0])+","+str(mvalue2[0])+","+str(cvalue2[1])+","+str(mvalue2[1])
        if int(cvalue2[0]) != int(mvalue2[0]):
            print "ERROR MISMATCH READS"
            print str(cvalue2[0]) + "," + str(mvalue2[0])
            error = True
        if int(cvalue2[1]) != int(mvalue2[1]):
            print "ERROR MISMATCH WRITES"
            print str(cvalue2[1]) + "," + str(mvalue2[1])
            error = True
if error:
    print "Error was detectd"
else:
    print "No errors detected"
