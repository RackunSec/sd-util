#!/usr/bin/env python3
#  sd-extractor-util - 2021 Douglas Berdeaux
#  Red Team tool for avoiding the leakage of credentials
#
#  extract the NTLMs: --extract
#  match the cracked NTLMs: --correlate
#
#  1. Run secretsdump and capture output to a dump file.
#  2. Run the extractor to take out only the NTLM hashes
#  3. Crack the NTLMs using your EC2 and Hashcat -m 1000
#  4. Bring the hashcat --show output back to here as a dump file.
#  5. correleate the hashcat dump to the secretsdump file.
#  6. Avoid a breach or potentially more work for IT depts everywhere.
#
import sys # for exit() / args / etc
import argparse # for arguments
import re # regexp matching
version="0.5.01.10 (Slimer)"
class prompt_color:
    bcolors = {
        'OKGREEN' : '\033[3m\033[92m ✔ ',
        'GREEN' : '\033[92m',
        'RED' : '\033[91m',
        'ENDC' : '\033[0m',
        'BOLD' : '\033[1m',
        'YELL' : '\033[33m\033[3m',
        'ITAL' : '\033[3m',
        'UNDER' : '\033[4m',
        'BLUE' : '\033[34m',
        'BUNDER': '\033[1m\033[4m',
        'WARN': '\033[33m   ',
        'COMMENT': '\033[37m\033[3m',
        'QUESTION': '\033[3m ',
        'INFO': ' ',
        'BLINK': '\033[5m'
    }
color = prompt_color.bcolors # create color object to use throughout.
print(f"""{color['GREEN']}
  ██████ ▓█████▄         █    ██ ▄▄▄█████▓ ██▓ ██▓
▒██    ▒ ▒██▀ ██▌        ██  ▓██▒▓  ██▒ ▓▒▓██▒▓██▒
░ ▓██▄   ░██   █▌ ▓███  ▓██  ▒██░▒ ▓██░ ▒░▒██▒▒██░
  ▒   ██▒░▓█▄   ▌ ████  ▓▓█  ░██░░ ▓██▓ ░ ░██░▒██░
▒██████▒▒░▒████▓   ▒▒▓  ▒▒█████▓   ▒██▒ ░ ░██░░██████▒
▒ ▒▓▒ ▒ ░ ▒▒▓  ▒   ░░▒  ░▒▓▒ ▒ ▒   ▒ ░░   ░▓  ░ ▒░▓  ░
░ ░▒  ░ ░ ░ ▒  ▒   ░    ░░▒░ ░ ░     ░     ▒ ░░ ░ ▒  ░
░  ░  ░   ░ ░  ░         ░░░ ░ ░   ░       ▒ ░  ░ ░
      ░     ░       ░      ░               ░      ░  ░
          ░                   ░            ░
                           ░                      ░
Version: {version}
{color['ENDC']}""")
def quit_me():
    print(f"{color['ENDC']}",end="")
    sys.exit()
parser = argparse.ArgumentParser()
parser.add_argument("--sd-dump", help="Specify the secretsdump.py output file to analyze.", type=argparse.FileType('r'), required=True, metavar='SECRETSDUMP_FILE')
parser.add_argument("--extract", help="Extract the NTLM hashes ONLY from the SD_DUMP file.",action="store_true")
parser.add_argument("--correlate", help="Correlate Hashcat pot dump file to SD_DUMP. (REQUIRES --hashcat-pot argument)",action="store_true")
parser.add_argument("--quiet", help="Do not print sensitive data to terminal.",action="store_true")
parser.add_argument("--hashcat-pot", help="Specify the Hashcat pot dump file to analyze.", metavar='HASHCAT_OUTPUT_FILE', type=argparse.FileType('r'),)
parser.add_argument("--output", help="Specify output file to put results into.", type=argparse.FileType('w'), metavar='OUTPUT_FILE')
parser.add_argument("--stats", help="Compile statistics for correlated secretsdump file.", action="store_true")
args = parser.parse_args()

#### WORKFLOW OF APP:
print(f"{color['OKGREEN']}{color['ENDC']} Secretsdump.py output file:{color['GREEN']} {args.sd_dump.name}")
if args.output:
    print(f"{color['OKGREEN']} {color['ENDC']}Writing to output file: {color['GREEN']}{args.output.name}")
#print(args) # debug
if args.extract: # we are doing a simple extraction on the file provided:
    print(f"{color['OKGREEN']} Dumping NTLM hashes, {color['BUNDER']}Press enter key when ready{color['ENDC']}{color['GREEN']} (q to quit) ... {color['RED']}")
    ans=input()
    if ans=="q" or ans == "Q":
        quit_me()
    else:
        for line in args.sd_dump:
            line_split = line.rstrip().split(":")
            if len(line_split)>=4:
                ntlm = line_split[3]
                if re.match("[A-Fa-f0-9]{32}",ntlm):
                    print(f"{ntlm}")
                    if args.output: # outputting to a file:
                        print(f"{ntlm}",file=args.output)
elif args.correlate:
    if args.hashcat_pot:
        print(f"{color['OKGREEN']}{color['ENDC']} correlating Hashcat pot dump file: {color['GREEN']}{args.hashcat_pot.name}{color['ENDC']}\n\tto secretsdump.py output file:{color['GREEN']} {args.sd_dump.name}")
        print(f" Press {color['BLINK']}ENTER KEY{color['ENDC']}{color['GREEN']} when ready{color['ENDC']}{color['GREEN']} ({color['RED']}q to quit{color['GREEN']}) ... {color['RED']}")
        ans=input()
        cracked_count=0 # counter
        distinct_cracked_count=0
        if ans=="q" or ans == "Q":
            quit_me()
        ## Flow-through
        # read the hashcat pot first to minimize our O(n)
        for line_cracked in args.hashcat_pot:
            distinct_cracked_count+=1
            hc_ntlm=line_cracked.rstrip().split(":")[0]
            passwd=line_cracked.rstrip().split(":")[1]
            if re.match("[A-Fa-f0-9]{32}",hc_ntlm):
                for line_sd in args.sd_dump:
                    if hc_ntlm in line_sd:
                        cracked_count+=1
                        if not args.quiet: # sensitive info turned off
                            if not args.output: # output to file instead of screen
                                print(f"{hc_ntlm}:{line_sd.rstrip()}")
                        if args.output: # print passwords only to a file instead
                            print(f"{passwd}",file=args.output)
            args.sd_dump.seek(0) # rewind
        print(f"{color['OKGREEN']} ({cracked_count}) total hashes cracked.")
        print(f"{color['OKGREEN']} ({distinct_cracked_count}) distinct hashes.")
    else:
        print(f"{color['RED']} You must provide a Hashcat output file to use the --correlate function.")
        quit_me()
quit_me() # done.
