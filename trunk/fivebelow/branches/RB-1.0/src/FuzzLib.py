'''
Created on Jul 27, 2011

@author: Steve
'''
import sys
import os
import re
from xml.dom.minidom import parseString
from shutil import copy2
from mmap import mmap

class fileFuzz(object):
    '''
    the main file fuzzer class that is used for creating and manipulating files
    - Steven Seeley 2010
    '''

    def __init__(self, samplefile):
        '''
        Constructor
        '''
        self.samplefile = samplefile
        
        # attempt to read the config file
        try:
            self.xmldata = open(os.path.dirname(__file__) + "\\..\\config\\config.xml").read()
        except:
            print ("(!) Configuration file not found!")
            sys.exit()
        # check that we can parse the XML config file
        try:
            self.xmldoc = parseString(self.xmldata)
        except:
            print ("(!) Configuration file is not XML compliant")
            sys.exit()
            
        # specify start and end fuzz byte locations
        self.fuzzstart = self.xmldoc.getElementsByTagName('start_byte_location')
        self.fuzzstart = self.fuzzstart.item(0).childNodes[0].data 
        self.fuzzend = self.xmldoc.getElementsByTagName('end_byte_location')
        self.fuzzend = self.fuzzend.item(0).childNodes[0].data
        
        # specify the number of bytes to fuzz with
        self.numberOfBytes = self.xmldoc.getElementsByTagName('numberOfBytes')
        self.numberOfBytes = int(self.numberOfBytes.item(0).childNodes[0].data)  
            
        # specify the location of where to fuzz at
        self.location = self.xmldoc.getElementsByTagName('location')
        self.location = str(self.location.item(0).childNodes[0].data)
        
        # specify the start and end buffer sizes
        self.start_buffer_size = self.xmldoc.getElementsByTagName('start_buffer_size')
        self.start_buffer_size = self.start_buffer_size.item(0).childNodes[0].data 
        self.end_buffer_size = self.xmldoc.getElementsByTagName('end_buffer_size')
        self.end_buffer_size = self.end_buffer_size.item(0).childNodes[0].data    
    
    def getSampleData(self, listFlag):
        f = open(self.samplefile, "r")
        if listFlag:
            fileData = list(f.read())
        else:
            fileData = f.read()
        f.close()
        return fileData
    
    # break down what we are fuzzing into meaningful knowledge
    def getFuzzLength(self):
        numberOfBytes = self.xmldoc.getElementsByTagName('numberOfBytes')
        numberOfBytes = int(numberOfBytes.item(0).childNodes[0].data) 
        if numberOfBytes > 8:
            print "(-) Number of bytes to fuzz with is too high"
            sys.exit()
        elif numberOfBytes == 8:
            return "DOUBLE DWORD"
        elif numberOfBytes == 4:
            return "DWORD"
        elif numberOfBytes == 2:
            return "WORD"
        return "odd number of bytes (%s)" % (numberOfBytes)
    
    def getFuzzbyte(self):
        fuzzbyte = self.xmldoc.getElementsByTagName('fuzzbyte')
        if self.fuzzingtechnique == "byteflip":
            return fuzzbyte.item(0).childNodes[0].data
        elif self.fuzzingtechnique == "buffersmash":
            return fuzzbyte.item(1).childNodes[0].data
    
    def getNumberOfLocations(self):
        matchvalue = re.compile(self.location)
        return re.finditer(matchvalue, self.getSampleData(False))
        
    def getIncriments(self):
        increments = self.xmldoc.getElementsByTagName('increments')
        return increments.item(0).childNodes[0].data 
    
    def getLocation(self):
        location = self.xmldoc.getElementsByTagName('location')
        return location.item(0).childNodes[0].data     
        
    # set methods
    def setTechniqueToUse(self, fuzzingtechnique):
        self.fuzzingtechnique = fuzzingtechnique
    
    def setModeToUse(self, fuzzingmode):
        self.fuzzingmode = fuzzingmode
    
    def setOutputFolder(self, outputFolder):
        # ok, so the user supply a directory, but does it exist?
        if os.path.isdir(outputFolder):
            if outputFolder[len(outputFolder)-1] != "\\":
                outputFolder += "\\"
            self.outputFolder = outputFolder
        else:
            print "(-) Fuzz folder doesn't exist!"
            sys.exit()
        
    def setAndCheckExtension(self): 
        self.extension = "".join(os.path.splitext( self.samplefile )[1:])       
        if self.extension == "":
            print ("(-) Please specify a sample file with an extension")
            sys.exit(1)
        return True
    
    # check methods
    def isValidFile(self):
        try:
            test = open(self.samplefile, 'r')
        except:
            return False
        test.close()
        return True
    
    def flipByte(self, fuzzedFile, position):
        fh = open(fuzzedFile, "r+b")
        fh.seek(position)
        fh.write(self.bytesToOverwriteWith)
        fh.close()
        
    def bufferSmashOLD(self, fuzzedFile, position, buffer):
        fh = open(fuzzedFile, "r+b")
        fh.seek(position)
        fh.write(buffer)
        fh.close()
        
    def bufferSmash(self, fuzzedFile, position, buffer):
        if len(buffer) < 1:
            print "(-) Buffer string is empty, check your config.xml file"
            sys.exit()
        f = open(fuzzedFile, 'r+')
        m = mmap(f.fileno(), os.path.getsize(fuzzedFile))
        origSize = m.size()
        #print "file size: %s" % origSize
        #print "position: %s" % position
        if position > origSize:
            position = origSize
        elif position < 0:
            position = 0
        m.resize(origSize + len(buffer))
        m[position+len(buffer):] = m[position:origSize]
        m[position:position+len(buffer)] = buffer
        m.close()
        f.close()

    # create a copy of our sample file and place it into the output folder
    def createCopy(self, count):
        copyfile = self.outputFolder + str(count) + self.extension
        copy2(self.samplefile, copyfile)
        print "\t--->\t"+copyfile
        return copyfile
    
    def startByteFlipping(self):
        fuzzbyte = self.getFuzzbyte()
        # get the actual byte that we are fuzzing with
        self.bytesToOverwriteWith = chr(int(fuzzbyte[2:], 16)) * int(self.numberOfBytes)
        count = 0
        for i in range(int(self.fuzzstart), int(self.fuzzend) + 1):
            fuzzedcopy = self.createCopy(count)
            self.flipByte(fuzzedcopy, (i*int(self.numberOfBytes)))
            count += 1
            
    def startBufferSmashing(self):
        incriments = self.getIncriments()
        f = open(self.samplefile,'r')
        mydataList = list(f.read())
        count = 0
        for index,char in enumerate(mydataList):
            if char == self.location:   
                for i in range(int(self.start_buffer_size), (int(self.end_buffer_size)+1), int(incriments)):
                    attackBuffer = chr(int(self.getFuzzbyte()[2:], 16)) * i
                    fdata = mydataList[:]
                    fdata.insert(index+1, attackBuffer)
                    copyfile = self.outputFolder + str(count) + self.extension
                    print "\t-->\t%s" % copyfile
                    try:
                        cf = open(copyfile,'w')
                    except:
                        print "(-) Cannot create fuzz file on disk"
                        sys.exit()
                    cf.write("".join(fdata))
                    cf.close()
                    count += 1
        # clean up
        f.close()
