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
from types import SimpleNamespace # for dot notation
import os # for terminal column width
import threading # he's going the distance. He's going for speeeeeeed.
## Version - update this (year.mo.day.subv)
version="0.5.18.03 (HBD Nana)"

search_string={} # filter string (for client names, domain names, etc, to test password policy)
## Colors class:
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
color = SimpleNamespace(** prompt_color.bcolors) # create color object to use throughout.
print(f"""{color.GREEN}
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
{color.ENDC}""")
def quit_me():
    print(f"{color.ENDC}",end="")
    sys.exit()
parser = argparse.ArgumentParser()
parser.add_argument("--sd-dump", help="Specify the secretsdump.py output file to analyze.", type=argparse.FileType('r'), required=True, metavar='SECRETSDUMP_FILE')
parser.add_argument("--extract", help="Extract the NTLM hashes ONLY from the SD_DUMP file.",action="store_true")
parser.add_argument("--correlate", help="Correlate Hashcat pot dump file to SD_DUMP. (REQUIRES --hashcat-pot argument)",action="store_true")
parser.add_argument("--quiet", help="Do not print sensitive data to terminal.",action="store_true")
parser.add_argument("--string", help="Specify a string to search for during the examination of stats.")
parser.add_argument("--hashcat-pot", help="Specify the Hashcat pot dump file to analyze.", metavar='HASHCAT_OUTPUT_FILE', type=argparse.FileType('r'),)
parser.add_argument("--output", help="Specify output file to put results into.", type=argparse.FileType('w'), metavar='OUTPUT_FILE')
#parser.add_argument("--stats", help="Compile statistics for correlated secretsdump file.", action="store_true")
args = parser.parse_args()

## Password stats (global so that threads can access them)
upper_lower_end_number=0
season_num=0
season_full_year=0
season_year=0
season_year_special=0
season_full_year_special=0
cracked_count=0 # counter
hc_line_num=0
distinct_cracked_hashes = [] # list of dictinct passwds
terminal_width=os.get_terminal_size().columns # placed down here in case terminal is resized during analysis.

#### Define methods here:
def analysis(passwd,hc_ntlm):
    global upper_lower_end_number
    global season_num
    global season_full_year
    global season_year
    global season_year_special
    global season_full_year_special
    global cracked_count # counter
    global hc_line_num
    global distinct_cracked_hashes # list of dictinct passwds
    global search_string
    global args
    terminal_width=os.get_terminal_size().columns # placed down here in case terminal is resized during analysis.
    cracked_count+=sd_dump_lines_clean.count(hc_ntlm) # sd_dump from using THIS tool will produce ONLY NTLMs!

    ## store the distinct count:
    if hc_ntlm not in distinct_cracked_hashes:
        distinct_cracked_hashes.append(hc_ntlm)
    hc_line_num+=1
    if re.match("[A-Fa-f0-9]{32}",hc_ntlm): # this is a valid NTLM
        if hc_ntlm in sd_dump_lines_clean:
            if re.match("^[A-Z][A-Za-z0-9]+[0-9]+$",passwd):
                upper_lower_end_number+=1
            if re.match("^(Spring|Summer|Fall|Winter)[0-9]+$",passwd):
                season_num+=1
            if re.match("^(Spring|Summer|Fall|Winter)(19|20)[0-9]{2}$",passwd):
                season_full_year+=1
            if re.match("^(Spring|Summer|Fall|Winter)(19|20|21|22|23|24|25)$",passwd):
                season_year+=1
            if re.match("^(Spring|Summer|Fall|Winter)(19|20|21|22|23|24|25)[^A-Za-z0-9_-]+$",passwd):
                season_year_special+=1
            if re.match("^(Spring|Summer|Fall|Winter)20[12][0-9][^A-Za-z0-9_-]+$",passwd):
                season_full_year_special+=1
            if not args.quiet: # sensitive info turned off
                if not args.output: # output to file instead of screen
                    print(f"{hc_ntlm}:{passwd}")
            if args.string != None:
                if search_string.raw.lower() in passwd.lower():
                    #print(f"{color.OKGREEN} {color.ENDC}Filter string discovered: {color.GREEN}{passwd}{color.ENDC}") # DEBUG
                    search_string.count+=sd_dump_lines_clean.count(hc_ntlm) # count this hash
                else:
                    for mangle in search_string.leet_dd: # this is a simple, deduped list
                        if re.match(mangle.lower(),passwd.lower()):
                            search_string.count+=1
                            #print(f"{color.OKGREEN} {color.ENDC}Filter string discovered: {color.GREEN}{passwd}{color.ENDC}") # DEBUG
#### WORKFLOW OF APP:
print(f"{color.OKGREEN}{color.ENDC} Secretsdump.py output file:{color.GREEN} {args.sd_dump.name}")
if args.extract: # we are doing a simple extraction on the file provided:
    print(f"{color.OKGREEN}{color.ENDC} Dumping NTLM hashes.\n\n Press {color.BLINK}{color.GREEN}ENTER KEY{color.ENDC} when ready{color.ENDC} ({color.RED}q to quit{color.ENDC}) ... {color.RED}\n")
    ans=input()
    if ans=="q" or ans == "Q":
        quit_me()
    else:
        for line in args.sd_dump:
            line_split = line.rstrip().split(":")
            if len(line_split)>=4:
                ntlm = line_split[3]
                if re.match("[A-Fa-f0-9]{32}",ntlm):
                    if(args.output):
                        print(f"{ntlm}",file=args.output)
                    else: # just print to the screen
                        print(f"{ntlm}")


elif args.correlate:
    if args.hashcat_pot:
        print(f"{color.OKGREEN}{color.ENDC} Correlating Hashcat pot dump file: {color.GREEN}{args.hashcat_pot.name}{color.ENDC}")
        print(f"\t{color.GREEN}↳ {color.ENDC}to secretsdump.py output file:{color.GREEN} {args.sd_dump.name}")
        if(args.string):
            search_string=SimpleNamespace(**search_string) # make a sane object
            search_string.raw=args.string # keep the raw value
            search_string.count=0 # token
            search_string.leet_snp={} # dafuq is this necessary?
            search_string.leet=SimpleNamespace(**search_string.leet_snp) # store all leetsp3ak here.
            search_string.leet_dd=[] # list of deduped l33tsp34ks
            ## L33tsp43k B310w:
            search_string.leet.a=re.sub("[aA]","4",search_string.raw)
            search_string.leet.b=re.sub("[bB]","8",search_string.raw)
            search_string.leet.e=re.sub("[eE]","3",search_string.raw)
            search_string.leet.i=re.sub("[iI]","1",search_string.raw)
            search_string.leet.g=re.sub("[Gg]","6",search_string.raw)
            search_string.leet.o=re.sub("[oO]","0",search_string.raw)
            search_string.leet.t=re.sub("[tT]","7",search_string.raw)
            search_string.leet.r=re.sub("[Rr]","2",search_string.raw)
            search_string.leet.s=re.sub("[Ss]","5",search_string.raw)
            ## Special operators:
            search_string.leet.a_at=re.sub("[aA]","@",search_string.raw)
            search_string.leet.i_l=re.sub("[iI]","l",search_string.raw)
            search_string.leet.s_dollar=re.sub("[Ss]","$",search_string.raw)
            ## multiple mangles:
            search_string.leet.a_b=re.sub("[bB]","8",search_string.leet.a)
            search_string.leet.a_g=re.sub("[gG]","6",search_string.leet.a)
            search_string.leet.a_e=re.sub("[Ee]","3",search_string.leet.a)
            search_string.leet.a_s=re.sub("[Ss]","5",search_string.leet.a)
            search_string.leet.a_i_l=re.sub("[lL]","3",search_string.leet.a)
            search_string.leet.a_i=re.sub("[iI]","1",search_string.leet.a)
            search_string.leet.a_o=re.sub("[oO]","3",search_string.leet.a)
            search_string.leet.a_t=re.sub("[tT]","7",search_string.leet.a)
            search_string.leet.a_r=re.sub("[Rr]","2",search_string.leet.a)
            search_string.leet.b_e=re.sub("[Ee]","3",search_string.leet.b)
            search_string.leet.b_g=re.sub("[Gg]","6",search_string.leet.b)
            search_string.leet.b_s=re.sub("[Ss]","5",search_string.leet.b)
            search_string.leet.b_i_l=re.sub("[lL]","3",search_string.leet.b)
            search_string.leet.b_i=re.sub("[iI]","1",search_string.leet.b)
            search_string.leet.b_o=re.sub("[oO]","3",search_string.leet.b)
            search_string.leet.b_t=re.sub("[tT]","7",search_string.leet.b)
            search_string.leet.b_r=re.sub("[Rr]","2",search_string.leet.b)
            search_string.leet.e_s=re.sub("[Ss]","5",search_string.leet.e)
            search_string.leet.e_g=re.sub("[Gg]","6",search_string.leet.e)
            search_string.leet.e_i_l=re.sub("[lL]","3",search_string.leet.e)
            search_string.leet.e_i=re.sub("[iI]","1",search_string.leet.e)
            search_string.leet.e_o=re.sub("[oO]","3",search_string.leet.e)
            search_string.leet.e_t=re.sub("[tT]","7",search_string.leet.e)
            search_string.leet.e_r=re.sub("[Rr]","2",search_string.leet.e)
            search_string.leet.i_s=re.sub("[Ss]","5",search_string.leet.i)
            search_string.leet.i_g=re.sub("[Gg]","6",search_string.leet.i)
            search_string.leet.i_o=re.sub("[oO]","3",search_string.leet.i)
            search_string.leet.i_t=re.sub("[tT]","7",search_string.leet.i)
            search_string.leet.i_r=re.sub("[Rr]","2",search_string.leet.i)
            search_string.leet.g_s=re.sub("[Ss]","5",search_string.leet.g)
            search_string.leet.g_o=re.sub("[oO]","3",search_string.leet.g)
            search_string.leet.g_t=re.sub("[tT]","7",search_string.leet.g)
            search_string.leet.g_r=re.sub("[Rr]","2",search_string.leet.g)
            search_string.leet.o_s=re.sub("[Ss]","5",search_string.leet.o)
            search_string.leet.o_t=re.sub("[tT]","7",search_string.leet.o)
            search_string.leet.o_r=re.sub("[Rr]","2",search_string.leet.o)
            search_string.leet.t_s=re.sub("[Ss]","5",search_string.leet.t)
            search_string.leet.t_r=re.sub("[Rr]","2",search_string.leet.t)
            ## ALL mangles:
            search_string.leet.all=re.sub("[eE]","3",search_string.leet.a_b)
            search_string.leet.all=re.sub("[iI]","1",search_string.leet.all)
            search_string.leet.all=re.sub("[Gg]","6",search_string.leet.all)
            search_string.leet.all=re.sub("[Oo]","0",search_string.leet.all)
            search_string.leet.all=re.sub("[Rr]","2",search_string.leet.all)
            search_string.leet.all=re.sub("[Ss]","5",search_string.leet.all)
            ## DEDUPLICATE LIST:
            for mangle in search_string.leet.__dict__:
                if search_string.leet.__dict__[mangle] not in search_string.leet_dd:
                    search_string.leet_dd.append(search_string.leet.__dict__[mangle])
            print(f"{color.OKGREEN}{color.ENDC} L33tsp43k dict built. String to search: {color.GREEN}{search_string.raw}{color.ENDC}")

        ## READY TO BEGIN:
        ## TODO: There HAS to be a better way to do this?:
        hashcat_pot_lines=args.hashcat_pot.readlines() # make a list rather than keep reading file.
        hashcat_pot_lines_clean = []
        for line in hashcat_pot_lines:
            hashcat_pot_lines_clean.append(line.rstrip()) # really? >_>
        del hashcat_pot_lines # destroy the raw copy
        ## TODO: There HAS to be a better way to do this?:
        sd_dump_lines=args.sd_dump.readlines() # make this a list as well for speed.
        sd_dump_lines_clean = []
        for line in sd_dump_lines:
            sd_dump_lines_clean.append(line.rstrip()) # really? >_>
        del sd_dump_lines # destroy the raw copy

        print(f"{color.OKGREEN}{color.ENDC} Hashcat pot built as list.{color.ENDC}")
        ## ASK USER TO BEGIN:
        print(f" \nPress {color.BLINK}{color.GREEN}ENTER KEY{color.ENDC} when ready{color.ENDC} ({color.RED}q to quit{color.ENDC}) ... {color.RED}",end="")
        ans=input()
        if ans=="q" or ans == "Q":
            quit_me()

        ## Flow-through
        for line_cracked in hashcat_pot_lines_clean: # hashcat_pot_lines is deduped by hashcat by default with "hashcat -m 1000 --show <file>"
            ## split up the hashcat pot file output: ntlm:passwd
            passwd=line_cracked.split(":")[1] # TODO - can this be a single call to split?
            hc_ntlm=line_cracked.split(":")[0]
            print(f"\r{color.YELL}({color.ENDC}{color.BOLD}{hc_line_num}{color.ENDC}{color.YELL}){color.ENDC}{color.BOLD} ",end="")
            print(f"Hashcat pot passwords analyzed. Current: ({passwd}) {color.ENDC}",end="\r")
            print(" "*(int(terminal_width)-3),end="")
            thread = threading.Thread(target=analysis, args=(passwd,hc_ntlm,))
            thread.start()
            thread.join()
        print(f"\r")
        print(" "*(int(terminal_width)-3))
        cracked_percent=round((cracked_count/len(sd_dump_lines_clean)*100),2)
        cracked_impact=""
        if(cracked_percent<=10):
            cracked_impact=f"{color.GREEN}{color.BOLD}LOW{color.ENDC}"
        if(cracked_percent>10 and cracked_percent<=20):
            cracked_impact=f"{color.YELL}{color.BOLD}MED{color.ENDC}"
        if(cracked_percent>20 and cracked_percent<=30):
            cracked_impact=f"{color.RED}{color.BOLD}HIGH{color.ENDC}"
        if(cracked_percent>30):
            cracked_impact=f"{color.RED}{color.BOLD}CRITICAL{color.ENDC}"        
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{cracked_count}{color.ENDC}/{color.GREEN}{len(sd_dump_lines_clean)}{color.ENDC}]({str(cracked_percent)}%) {color.GREEN}total{color.ENDC} hashes cracked.",end="")
        print(f" - IMPACT: {cracked_impact}")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{len(distinct_cracked_hashes)}/{color.GREEN}{cracked_count}{color.ENDC}] {color.GREEN}distinct{color.ENDC} hashes.")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{upper_lower_end_number}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Alphanum beginning with upper and ending with number.{color.ENDC}\"")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{season_num}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Season capitalized ending with number.{color.ENDC}\"")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{season_full_year}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Season capitalized ending with full year.{color.ENDC}\"")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{season_year}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Season captialized ending with two-digit year.{color.ENDC}\"")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{season_year_special}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Season capitalized ending with two-digit year and special character.{color.ENDC}\"")
        print(f"{color.OKGREEN} {color.ENDC}[{color.GREEN}{season_full_year_special}/{cracked_count}{color.ENDC}] passwords in form of: \"{color.GREEN}Season capitalized ending with full year and special character.{color.ENDC}\"")
        if args.string:
            print(f"\n{color.OKGREEN} {color.ENDC}Filter string {search_string.raw} discovered: ({search_string.count}) times.")
    else:
        print(f"{color.RED} You must provide a Hashcat output file to use the --correlate function.")
        quit_me()
print("\n")
quit_me() # done.
