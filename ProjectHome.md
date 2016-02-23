
```
   _____          ___      __          
  / __(_)  _____ / _ )___ / /__ _    __
 / _// / |/ / -_) _  / -_) / _ \ |/|/ /
/_/ /_/|___/\__/____/\__/_/\___/__,__/ 

```

# introduction #

This is a file fuzzer that I created over a game of texas hold'em one night whilst smashing down
to many bourbon and cokes.

Nicknamed fivebelow because during the game, we decided to remove numbers 5 and below so that we played
with only numbers 6-10, jack, queen, king and aces.

This enabled us to increase our chances of a good hand as there was only 3 of us playing. I figured that
I may as well attempt to increase my chances of finding some bugs too.

To continue with the style and theme (and to mask my laziness), the fuzzer has been designed with simplicity
and attempts to solve some problems that were identified in other simple file fuzzers.

I have compiled the engine into a IA-32 - 32bit standalone executable using py2exe so that users
do not have to worry about interdependencies with python libraries such as pydasm or pydbg.

# configuration #

The configuration file is located in <fivebelow dir>\config\config.xml. Before running, ensure that your configuration folder and file exists in the fivebelow folder.

The config file consists of:

  * standard "fuzztests" which are the fuzz test cases.
  * global parameters to set for fuzzing

## Global options ##

The researcher can configure the fuzzer the following way:

  * logpath: The log path where fuzz logs are generated after a fuzzing run
  * time\_delay: The amount of time to wait before terminating the process. That way if the process hangs, it will be canned.
  * startfile/endfile: the fuzz files to start and end at. If you generate 2000 files, you may only want to fuzz half now and do more later
  * arguments: the arguments to include. By default it will set {FILE} indicating just a file as the argument.

## Fuzz Tests ##

Additional, certain parameters can be configured when generating files:

  * fuzz byte: the byte to use for fuzzing with. Specified so that the number of fuzz files does not go beyond 0xffffffff.
  * start\_byte\_location/end\_byte\_location: the location in the file to start/end fuzzing at
  * numberOfBytes: is the number of bytes to fuzz with, eg typically only 2 or 4. However you may want to test with more bytes.
  * start\_buffer\_size/end\_buffer\_size: the start/end sizes of buffer strings to test with.
  * increments: the value to increment with.
  * location: the location in the file to fuzz at.

# example usage #

## fuzz file generation ##

When generating fuzz files, you must include the mandatory switches -i and -o to specify the sample
file and output fuzz folder. Logging has been disabled in the file generation process, however maybe
included in future releases.

To generate your fuzz files using the byte flipping technique, use the mode 'generate' along with the
technique 'byteflip'

  * **C:\fivebelow> fivebelow.exe -m generate -t byteflip -i "c:\fuzz\samples\sample.jpg" -o "c:\fuzz\jpg"**
  * **C:\fivebelow> fivebelow.exe -m generate -t buffersmash -i "c:\fuzz\samples\sample.vwr" -o "c:\fuzz\vwr"**

## file fuzzing ##

When fuzzing, you must include the mandatory switches -e and -o. You can turn logging on by using the -l
flag, however you must ensure that the 'logpath' value is set in the config file and that the directory
actually exists.

For example, to fuzz the binary `"VisiWaveReport.exe"`, specifying the location of the fuzz files "c:\fuzz\vwr"
and turning logging on, you would do:

  * **C:\fivebelow> fivebelow.exe -m fuzz -e `"C:\Program Files\VisiWave Site Survey\VisiWaveReport.exe"` -o "c:\fuzz\vwr" -l**