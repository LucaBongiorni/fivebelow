'''
Created on Jul 28, 2011

@author: Steve
'''

#import os.path
import os
#import time
import sys
import threading
#import binascii
import glob
import time
import random
from decimal import Decimal, getcontext
from pydbg import *
from pydbg.defines import *
from xml.dom.minidom import parseString

class monitor(object):
    '''
    the main monitoring class that is used for monitoring the processes and logging
    - Steven Seeley 2010
    '''

    def __init__(self, executable, fuzzfolder):
        '''
        Constructor
        '''
        self.executable = executable
        self.logging = False
        # change this for the configuration file
        #self.timeout = 4
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
            
        # let the log file element
        self.logpath = self.xmldoc.getElementsByTagName('logpath')
        self.logpath = self.logpath.item(0).childNodes[0].data
        
        # set the fuzz folder
        if fuzzfolder[len(fuzzfolder)-1] != "\\":
            fuzzfolder += "\\"
        self.fuzzfolder = fuzzfolder
        
        if not os.path.exists(self.fuzzfolder):
            print "(-) fuzz folder does not exist"
            sys.exit()

        # number of files in our fuzz directory
        # this seems like a bit of effort under windows
        # we don't need to access escape_dict or convertStrtoRaw() again
        
        escape_dict={'\a':r'\a',
           '\b':r'\b',
           '\c':r'\c',
           '\f':r'\f',
           '\n':r'\n',
           '\r':r'\r',
           '\t':r'\t',
           '\v':r'\v',
           '\'':r'\'',
           '\"':r'\"',
           '\0':r'\0',
           '\1':r'\1',
           '\2':r'\2',
           '\3':r'\3',
           '\4':r'\4',
           '\5':r'\5',
           '\6':r'\6',
           '\7':r'\7',
           '\8':r'\8',
           '\9':r'\9'}

        def convertStrtoRaw(text):
            """Returns a raw string representation of text"""
            new_string=''
            for char in text:
                try: new_string+=escape_dict[char]
                except KeyError: new_string+=char
            return new_string
        
        # get a sample file from the fuzz directory so that we can get 
        # the extension
        self.samplefile = random.choice(os.listdir(self.fuzzfolder))
        ext = "".join(os.path.splitext( self.samplefile )[1:])
        
        # finally, we get the number of files -1 to accommodate for its own directory :/
        self.numberOfFuzzFiles = len(glob.glob(convertStrtoRaw(self.fuzzfolder+"*"+ext)))-1
        
        # get the timeout value
        self.timeout_delay = self.xmldoc.getElementsByTagName('timeout_delay')
        self.timeout_delay = int(self.timeout_delay.item(0).childNodes[0].data)
        
        # get the startfile and endfile values
        self.startfile = self.xmldoc.getElementsByTagName('startfile')
        self.startfile = int(self.startfile.item(0).childNodes[0].data)
        self.endfile = self.xmldoc.getElementsByTagName('endfile')
        self.endfile = int(self.endfile.item(0).childNodes[0].data)
        
        # if the user is just stupid and putting large values into the config
        if self.numberOfFuzzFiles < self.endfile:
            print ("(-) End file is to large! You have only %s files to test" 
            % (self.numberOfFuzzFiles))
            sys.exit()
        # else, must be all good, lets get the total fuzzing time
        else:
            self.numberOfFuzzFiles = self.endfile - self.startfile
            # calculate the approximate total time to fuzz to 6 decimal places
            getcontext().prec = 6
            self.fuzzTime = Decimal(self.timeout_delay) * Decimal(self.numberOfFuzzFiles)
            
        # get the arguments
        self.arguments = self.xmldoc.getElementsByTagName('arguments')
        self.arguments = str(self.arguments.item(0).childNodes[0].data)
        
    # get methods
    def getExecutableName(self):
        temp = self.executable.split("\\")
        return temp[len(temp)-1]
    
    def getExtension(self):
        return "".join(os.path.splitext( self.samplefile )[1:])
    
    def getCalculatedFuzzTime(self):
        """ 
        gets the rounded time to fuzz value
        so that we know how long this might actually take..    
        """
        if self.fuzzTime > 60:
            self.fuzzTime = self.fuzzTime / Decimal(60)
            if self.fuzzTime > 60:
                self.fuzzTime = self.fuzzTime / Decimal(60)
                return str(self.fuzzTime), "hours"
            return str(self.fuzzTime), "minutes"
        return str(self.fuzzTime), "seconds"
            
    
    # set methods
    def setLoggingOn(self):
        # set the flag and create our logfile
        self.logging = True
        if self.logging:
            time = self.timer().replace(" ", "_").replace(":",".")
            logfile = ("%sfivebelow_fuzzlog_%s.txt" % (self.logpath,time))
            #print logfile
            try:
                self.log = open(logfile,'w')
            except:
                print "(-) Error, log directory path doesnt exist"
                sys.exit()
    
    def setOutputFolder(self, outputFolder):
        if outputFolder[len(outputFolder)-1] != "\\":
            outputFolder += "\\"
        self.outputFolder = outputFolder
        
    def isValidFile(self):
        return os.path.isfile(self.executable)
    
    def isValidExtension(self):
        if self.executable.find(".") == -1:
            return False
        else:
            if self.executable.endswith("exe"):
                return True
        return False
    
    def isValidOutputFolder(self):
        return os.path.exists(self.fuzzfolder)
    
    def findPid(self, dbg, name):
        namel = name.lower()
        for (pid, proc_name) in dbg.enumerate_processes():
            if proc_name.lower() == namel:
                return pid
        return -1    
    
    def timer(self):
        now = time.localtime(time.time())
        return time.asctime(now)
    
    def dumpRegister(self, pydbg, address):
        """
        Dump the memory if the register points to a valid + accessible address

        Parameters:
        pydbg   - pydbg object that's attached to a process
        address - integer. The memory address to read

        Return:
        The first 8 bytes of the data in the memory
        """
        try:
            dump = "-> 0x%s" % pydbg.read_process_memory(address, 4).encode("hex")
            
            if dump == "FAILED":
                dump = ""
        except:
            dump = ""
        return dump
    
    
    def checkAccessViolation(self, dbg):
        # We skip first-chance exceptions
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED
        print "\n\t(!) Detected !!! ACCESS VIOLATION !!!\n"  
        
        # thanks _sinn3r
        exceptionRecord = dbg.dbg.u.Exception.ExceptionRecord
        write_violation = exceptionRecord.ExceptionInformation[0]
        violationAddr   = "%08x" %exceptionRecord.ExceptionInformation[1]
        # Violation type
        if write_violation:
            violation = ("WRITE violation on %s" % (violationAddr))
        else:
            violation = ("READ violation on %s" % (violationAddr))
        
        reg  = "\t\tEAX = 0x%08x %s\r\n" %(dbg.context.Eax, self.dumpRegister(dbg, dbg.context.Eax))
        reg += "\t\tECX = 0x%08x %s\r\n" %(dbg.context.Ecx, self.dumpRegister(dbg, dbg.context.Ecx))
        reg += "\t\tEDX = 0x%08x %s\r\n" %(dbg.context.Edx, self.dumpRegister(dbg, dbg.context.Edx))
        reg += "\t\tEBX = 0x%08x %s\r\n" %(dbg.context.Ebx, self.dumpRegister(dbg, dbg.context.Ebx))
        reg += "\t\tESP = 0x%08x %s\r\n" %(dbg.context.Esp, self.dumpRegister(dbg, dbg.context.Esp))
        reg += "\t\tEBP = 0x%08x %s\r\n" %(dbg.context.Ebp, self.dumpRegister(dbg, dbg.context.Ebp))
        reg += "\t\tESI = 0x%08x %s\r\n" %(dbg.context.Esi, self.dumpRegister(dbg, dbg.context.Esi))
        reg += "\t\tEDI = 0x%08x %s\r\n" %(dbg.context.Edi, self.dumpRegister(dbg, dbg.context.Edi))
        reg += "\t\tEIP = 0x%08x\r\n\r\n" %dbg.context.Eip
        
        # just disasm @ the crashed location for window
        windowdisam = dbg.disasm_around(dbg.context.Eip, 0)
        
        # real disasm
        disam = dbg.disasm_around(dbg.context.Eip, 15)
        instruction_dump = ""
        for (addr, instruction) in disam:
            #Dump the assembly instructions
            if addr == dbg.context.Eip:
                instruction_dump += "\t\t0x%08x  %s  <--- Crash\r\n" %(addr, instruction)
            else:
                instruction_dump += "\t\t0x%08x  %s\r\n" %(addr, instruction)
        
        instruction_dump_window = ""
        for (addr, instruction) in windowdisam:
            instruction_dump_window += "0x%08x : %s" %(addr, instruction)

        output = ("\t(!) %s\r\n" % (violation))
        output += ("\t(!) Crash @ %s" % (instruction_dump_window))
        
        log_output = ("\n\t(!!) Detected !!! ACCESS VIOLATION !!!\r\n\r\n" )
        log_output += ("\t(!) Type: %s\r\n" % (violation))
        log_output += ("\t(!) Breakdown: \r\n\r\n%s" % (instruction_dump))
        log_output += ("\n\t(!) Registers @ crash time:\r\n\r\n%s" % (reg))
        if self.logging:
            self.log.write(log_output)
    
        print output
        print "\t(!) Registers @ crash time:\r\n"
        print reg
        dbg.terminate_process()
        return DBG_EXCEPTION_NOT_HANDLED
    
    def watch(self, pydbg):
        time.sleep(self.timeout_delay)
        if pydbg.debugger_active:
            try:
                pydbg.terminate_process()
            except:
                print "(-) Couldnt terminate process"
                return 1
            
            return DBG_CONTINUE
    
    def loadExecutable(self, i):
        dbg = pydbg()
        t = threading.Thread(target=self.watch, args=(dbg,))
        if self.arguments == "{FILE}":
            dbg.load(self.executable, self.fuzzfolder + str(i) + self.getExtension())
        else:
            tempfuzzfile = self.fuzzfolder + str(i) + self.getExtension()
            tempargs = self.arguments.replace("{FILE}", tempfuzzfile)
            dbg.load(self.executable, tempargs)
            
        dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.checkAccessViolation)
        pid = self.findPid(dbg, self.getExecutableName())
        whatWeAreFuzzing = ("(+) Fuzzing pid %s with file %s%s%s" 
        % (pid,self.fuzzfolder, str(i), self.getExtension()))
        if self.logging:
            self.log.write(whatWeAreFuzzing + "\r\n")
        print whatWeAreFuzzing
        t.start()
        dbg.debug_event_loop()  
        
        
    def startFuzzing(self):
        # for the the number of files specified by the analyst
        for i in range(self.startfile,self.endfile+1):
            t = threading.Thread(target=self.loadExecutable, args=(i,))
            t.start()
            t.join()