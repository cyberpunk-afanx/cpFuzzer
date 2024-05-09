import sys
import os

def usage():
    print("python3 cpfuzzer.py <binary> > fuzzerFile.py")
    print("cpfuzzer <binary> > fuzzerFile.py")


start_template = '''from pwn import *
import curses
import time
import signal
'''
if(len(sys.argv) > 1):
    start_template += '''exe = context.binary = ELF(args.EXE or \'./''' + sys.argv[1] + '''\')''' 

main_template = '''
def start(argv=[], *a, **kw):
    \'\'\'Start the exploit against the target.\'\'\'
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def mutagen(): # create crash
    maxLen=1024
    startSymb1 = 65
    startSymb2 = 97
    startSymb3 = 97
    startSymb4 = 97
    stopSymb1 = 90
    stopSymb2 = 122
    stopSymb3 = 122
    stopSymb4 = 122
    count = 0
    junk = ""
    queue = []

    for i in range(startSymb1, stopSymb1+1):
        count += 1
        if(count > maxLen):
            return queue
        for j in range(startSymb2, stopSymb2+1):
            count += 1
            if(count > maxLen):
                return queue
            for k in range(startSymb3, stopSymb3+1):
                count += 1
                if(count > maxLen):
                    return queue
                for m in range(startSymb4, stopSymb4+1):
                    junk += chr(i) + chr(j) + chr(k) + chr(m)
                    count += 1
                    queue.append(junk)
                    if(count > maxLen):
                        return queue

def detect_crash(junk): # detect count of crash 4 last bytes
    d = 0
    ascii_values = [ord(char) for char in junk]

    d = ascii_values[0]
    d = (d - ord("A"))*26*26*26*4
    addr = d

    d = ascii_values[1]
    d = (d - ord("a"))*26*26*4
    addr = addr + d

    d = ascii_values[2] 
    d = (d - ord("a"))*26*4
    addr = addr + d

    d = ascii_values[3]
    d = (d - ord("a"))*4
    addr = addr + d

    return addr

def signal_handler(signal, frame):
    print("\\n30 seconds and exit...")
    time.sleep(30)
    sys.exit(0)

def update_form(stdscr, data, input_data, crash_data):
    # Clear the screen
    stdscr.clear()
    stdscr.addstr(0,0,\'\'\'
             _                                 _    _____                       
   ___ _   _| |__   ___ _ __ _ __  _   _ _ __ | | _|  ___|   _ ___________ _ __ 
  / __| | | | '_ \ / _ \ '__| '_ \| | | | '_ \| |/ / |_ | | | |_  /_  / _ \ '__|
 | (__| |_| | |_) |  __/ |  | |_) | |_| | | | |   <|  _|| |_| |/ / / /  __/ |   
  \___|\__, |_.__/ \___|_|  | .__/ \__,_|_| |_|_|\_\_|   \__,_/___/___\___|_|   
       |___/                |_|                                                ——Powered By AFANX                             

                                [ build 19042024 ]  
                                
    \'\'\')

    stdscr.addstr(13, 0, "[ BASE ADDRESS ] : " + hex(exe.address))
    stdscr.addstr(14, 0, "[ eh_frame_addr ] : " + hex(exe.get_section_by_name('.eh_frame').header.sh_addr))
    stdscr.addstr(15, 0, "[ START OFFSET ] : " + hex(exe.header.e_entry))
    stdscr.addstr(16, 0, "[ OFFSET ] : " + hex(exe.read(exe.header.e_entry, 0x40).find(b'\\x48\\xc7\\xc7')))
    stdscr.addstr(17, 0, "[ MAIN ADDRESS ] : " + hex(u32(exe.read(exe.header.e_entry + exe.read(exe.header.e_entry, 0x40).find(b'\\x48\\xc7\\xc7') + 3, 4))))

    stdscr.addstr(18, 0, "[ TIME ] : " + str(data) + ' sec')
    stdscr.addstr(19, 0, "[ LEN DATA ] : " + str(len(input_data[data])))
    stdscr.addstr(20, 0, "[ DATA ] : " + input_data[data])

    io = start()

    ### start here

    # io.recvuntil(b'Enter your name: ')

    ### stop here
    
    io.sendline(input_data[data].encode())

    if(io.poll(block=True) == -11):
        crash_data.append(input_data[data])
        stdscr.addstr(11, 0, "[ crash data ] : " + input_data[data])
        stdscr.addstr(12, 0, "[ lenght crash data ] : " + str(detect_crash(input_data[data][len(input_data[data])-4:])) + " ")

        with open('crash_'+str(detect_crash(input_data[data][len(input_data[data])-4:]))+'.txt', 'w') as crash_file:
            crash_file.write(input_data[data])

        io.interactive()
        
    io.close()

    # Refresh the screen
    stdscr.refresh()


def update_window(stdscr, queue_files, crash_data, type="bof"):
    # Set up the terminal for curses
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    
    # Initial data
    data = 0
    
    if(type == "bof"):
        # Main loop
        while True:
            # Update the form with the current data
            update_form(stdscr, data, queue_files, crash_data)
            
            # Increment the data
            data += 1
            
            # Wait for a short interval
            time.sleep(0.1)

def start_cpunker_fuzz():

    queue_files = mutagen()
    crash_data = ['']


    signal.signal(signal.SIGINT, signal_handler)

    # Wrap the main function in curses.wrapper()
    curses.wrapper(update_window, queue_files, crash_data)
    return 

def main():
    start_cpunker_fuzz()

if __name__ == '__main__':
    main()'''

def main():
    if(len(sys.argv) > 1):
        if(sys.argv[1] != ""):
            try:
                print(start_template + main_template)
            except Exception as ex:
                print("[-] " + str(ex))
                print("[-] " + "can\'t create tamplate file")
    else:
        usage()
        return

if __name__ == '__main__':
    main()