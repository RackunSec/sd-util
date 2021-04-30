#!/usr/bin/env python3
#  sd-extractor-util - 2021 Douglas Berdeaux
#  Red Team tool for avoiding the leakage of credentials
#
#  extract the NTLMs: --extract
#  match the cracked NTLMs: --coorelate
#
#  1. Run secretsdump and capture output to a dump file.
#  2. Run the extractor to take out only the NTLM hashes
#  3. Crack the NTLMs using your EC2 and Hashcat -m 1000
#  4. Bring the hashcat --show output back to here as a dump file.
#  5. Cooreleate the hashcat dump to the secretsdump file.
#  6. Avoid a breach or potentially more work for IT depts everywhere.
#
import sys # for exit() / args / etc
import argparse # for arguments
class prompt_color:
    bcolors = {
        'OKGREEN' : '\033[3m\033[92m ✔ ',
        'GREEN' : '\033[92m',
        'FAIL' : '\033[3m\033[91m ✖ ',
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
        'INFO': ' '
    }
color = prompt_color.bcolors # create color object to use throughout.
print(f"""{color['GREEN']}
  ██████ ▓█████▄    ▓█████ ▒██   ██▒▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███
▒██    ▒ ▒██▀ ██▌   ▓█   ▀ ▒▒ █ █ ▒░▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒
░ ▓██▄   ░██   █▌   ▒███   ░░  █   ░▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒
  ▒   ██▒░▓█▄   ▌   ▒▓█  ▄  ░ █ █ ▒ ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄
▒██████▒▒░▒████▓    ░▒████▒▒██▒ ▒██▒  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒
▒ ▒▓▒ ▒ ░ ▒▒▓  ▒    ░░ ▒░ ░▒▒ ░ ░▓ ░  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
░ ░▒  ░ ░ ░ ▒  ▒     ░ ░  ░░░   ░▒ ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒       ░      ░ ▒ ▒░   ░▒ ░ ▒░
░  ░  ░   ░ ░  ░       ░    ░    ░    ░        ░░   ░   ░   ▒   ░          ░      ░ ░ ░ ▒    ░░   ░
      ░     ░          ░  ░ ░    ░              ░           ░  ░░ ░                   ░ ░     ░
          ░                                                     ░
{color['ENDC']}""")
parser = argparse.ArgumentParser()
parser.add_argument("--sd-dump", help="Specify the secretsdump.py output file to analyze.", type=argparse.FileType('r'))
parser.add_argument("--extract", help="Extract the NTLM hashes ONLY from the SD_DUMP file.",action="store_true")
parser.add_argument("--coorelate", help="Coorelate Hashcat pot dump file to SD_DUMP. (REQUIRES --hashcat-pot argument)",action="store_true")
parser.add_argument("--hashcat-pot", help="Specify the Hashcat pot dump file to analyze.")
args = parser.parse_args()

#print(args) # debug
if args.extract: # we are doing a simple extraction on the file provided:
    print(f"{color['OKGREEN']} ntdis.dit file: {args.sd_dump}{color['ENDC']}\n")
    for line in args.sd_dump:
        line_split = line.rstrip().split(":")
        print(f"{line_split[3]}")
sys.exit()
