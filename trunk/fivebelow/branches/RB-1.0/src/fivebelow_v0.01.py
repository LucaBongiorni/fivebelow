'''
Created on Jul 27, 2011

@author: Steve
test
'''
import sys
import re
import os
import time
from optparse import OptionParser
from FuzzLib import fileFuzz
from monitor import monitor

usage = "./%prog -m <mode> [<options>]"
usage += "\nExample: ./%prog -m generate -t byteflip -i c:\\fuzz\\samples\\sample.jpg -o c:\\fuzz\\jpg\\"

parser = OptionParser(usage=usage)
parser.add_option("-o", type="string",action="store", dest="fuzzfolder",
                  help="Fuzz folder, where all fuzz files go")
parser.add_option("-i", type="string", action="store", dest="samplefile",
                  help="sample file")
parser.add_option("-e", type="string", action="store", dest="executable",
                  help="The full path to the executable")
parser.add_option("-m", type="string", action="store", dest="mode",
                  help="The mode to run in (see README.txt)")
parser.add_option("-t", type="string", action="store", dest="technique",
                  help="The fuzz technique to use (see README.txt)")
parser.add_option("-l", default=False, action="store_true", dest="log",
                  help="Turn logging on")

(options, args) = parser.parse_args()

def banner():
    banner = ("\n\t| -----------------------------|\n")
    banner += ("\t| FiveBelow - the file fuzzer  |\n")
    banner += ("\t| by mr_me --------------------|\n")
    return banner

if len(sys.argv) < 4:
    print banner()
    parser.print_help()
    sys.exit(1)

def timer():
    now = time.localtime(time.time())
    return time.asctime(now)  
    
def generateModeConfirmationAndProceed(fuzzer):
    print ("(+) File format set to %s" % (fuzzer.extension))
    ready = raw_input("(+) Are these settings correct? ")
    if ready[0] == "y" or ready[0] == "Y":
        print ("(+) Fuzz generation started at %s\n" % (timer()))
        if options.technique == "buffersmash":
            fuzzer.startBufferSmashing()
        elif options.technique == "byteflip":
            fuzzer.startByteFlipping()
    else:
        print "(!) Reset the configuration file to the appropriate settings"
        sys.exit()
    print ("\n(+) Fuzz generation completed at %s\n" % (timer()))
            
def processMode():
    if options.mode == "generate":
        if not options.samplefile:
            print "(!) Please specify a sample file"
            sys.exit()  
        # create a new filefuzzer with our sample file
        fuzzer = fileFuzz(options.samplefile)
        fuzzer.setTechniqueToUse(options.technique)
        fuzzer.setModeToUse(options.mode)
        if options.fuzzfolder:
            fuzzer.setOutputFolder(options.fuzzfolder)
        else:
            print "(-) Please supply a fuzz folder to store fuzzed files"
            sys.exit()
        
        # if the file is real and has an extension..
        if fuzzer.isValidFile() and fuzzer.setAndCheckExtension():
            # no switch in python, checking for the techniques
            if options.technique == "byteflip":
                print ("(+) Fuzz generation based on byte flipping")
                print ("(+) Using a %s as the size" % (fuzzer.getFuzzLength()))
                print ("(+) Byte %s is set as the flip byte" % (fuzzer.getFuzzbyte()))
                print ("(+) Fuzzing between size offsets %s and %s" % (fuzzer.fuzzstart, fuzzer.fuzzend))
                generateModeConfirmationAndProceed(fuzzer)
                    
            elif options.technique == "buffersmash":
                print ("(+) Fuzz generation based on buffer smashing")
                print ("(+) Fuzzing between size offsets %s and %s" % (fuzzer.start_buffer_size, fuzzer.end_buffer_size))
                print ("(+) Creating fuzz increments of %s" % (fuzzer.getIncriments()))
                print ("(+) Using a '%s' for the location to fuzz at" % (fuzzer.getLocation()))
                print ("(+) Byte %s is set as the buffer value" % (fuzzer.getFuzzbyte()))
                generateModeConfirmationAndProceed(fuzzer)
            else:
                print "(-) Incorrect technique specified, check your settings"
                sys.exit()
        else:
            print "(-) Invalid sample file, check your path"
            sys.exit()
            
    elif options.mode == "fuzz":
        if not options.executable:
            print "(!) Please specify an executable to fuzz"
            sys.exit()
        elif not options.fuzzfolder:
            print "(!) Please specify the fuzz folder path"
            sys.exit()
        # create a monitoring object with our executable and fuzz folder of files
        monitorAndLog = monitor(options.executable, options.fuzzfolder)
        if monitorAndLog.isValidFile() and monitorAndLog.isValidExtension():
            if monitorAndLog.isValidOutputFolder():
                confirmSettings = ("(+) Fuzzing file format '%s'\r\n" % (monitorAndLog.getExtension()))
                confirmSettings += ("(+) Fuzzing time is estimated to be <= %s %s\r\n" % (monitorAndLog.getCalculatedFuzzTime()))
                confirmSettings += ("(+) Fuzzing with %s files\r\n" % (monitorAndLog.numberOfFuzzFiles))
                confirmSettings += ("(+) Fuzzing executable %s \r\n" % (options.executable))
                print confirmSettings
                ready = raw_input("(+) Are these settings correct? ")
                if ready[0] == "y" or ready[0] == "Y":
                    confirmSettings += ("(+) Fuzzing started at %s\r\n" % (timer()))
                    if options.log:
                        print "(+) Logging into '%s'" % (monitorAndLog.logpath)
                        monitorAndLog.setLoggingOn()
                        monitorAndLog.log.write(banner())
                        monitorAndLog.log.write(confirmSettings)
                    monitorAndLog.startFuzzing()
                    print ("(+) Fuzzing completed at %s" % (timer()))
                    if options.log:
                        monitorAndLog.log.close()
                else:
                    print "(!) Reset the configuration file to the appropriate settings"
                    sys.exit() 
        else:
            print "(-) Executable doesn't exist on system, check your path"
            sys.exit()
    else:
        print "(-) Incorrect mode specified, check your settings"
        sys.exit()                
    
def main():
    print banner()
    processMode()

if __name__ == '__main__':
    main()