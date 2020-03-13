import sys

def printUsage():
    s = 'USAGE: memlogCheck.py myFile.cachesim myFile.memlog'
    print s
    exit()

def checkCMDLineArgs(argv):
    if len(argv) != 3:
        print '0'
        printUsage()
    file1 = argv[1]
    file1ext = file1[-9:]
    if file1ext != ".cachesim":
        print 'A'
        printUsage()
    file2 = argv[2]
    file2ext = file2[-7:]
    if file2ext != ".memlog":
        print 'B'
        printUsage()

def scanForStart(file):
    for line in file:
        print line
        check = line[0]
        print '\'' + check + '\''
        print 'NEXT'
        if check == "\t":
            print 'bingo'
            print check
            print 'dingo'
            break
    return file.tell()

checkCMDLineArgs(sys.argv)
print 'f1 is' + sys.argv[1]
print 'f2 is' + sys.argv[2]
f1 = open(sys.argv[1], 'r')
f2 = open(sys.argv[2], 'r')
f1Pos = scanForStart(f1)
f2Pos = scanForStart(f2)
f1.seek(f1Pos)
line = f1.readline();
print f1Pos
print "'" + line + "'"
line = f1.readline();
""" print "'" + line + "'"
line = f1.readline();
print "'" + line + "'"
line = f1.readline();
print "'" + line + "'" """
print 'yay'
