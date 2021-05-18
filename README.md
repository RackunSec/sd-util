# Secretsdump Password Analysis Utility
Secretsdump.py Utility for Extracting and Coorelating Hashes and Avoiding User Data Breaches During Red Team Engagements. Using this tool, you can avoid breaching the rules of engagement, or breaching the client's sensitive data, by never exfiltrating the usernames of the domain from the secretsdump.py output. 
1. Run secretsdump
2. Extract the NTLMs and crack em
3. Correlate them back to the secretsdump output and show stats
### STEP 0x00: RUN SECRETSDUMP.PY
Run secretsdump.py against the domain controller and use the `-output` argument to save to a file: `client-sd-output.txt`
### STEP 0x01: EXTRACT NTLM HASHES
Extract JUST the NTML hashes for your cracking rig.
```
./sd-util.py --sd-dump client-sd-output.txt --extract --output client-sd-output-ntlms.txt
```
### STEP 0x02: CRACK THE HASHES WITH HASHCAT
Self explanatory: Copy your hashes file, `client-sd-output-ntlms.txt` to your cracking rig and crackem.
### STEP 0x03: CREATE POT FILE OUTPUT FROM NTLMS
Self explanatory: Run hashcat to show the cracked passwords and dump to a file:
```
hashcat --show -m 1000 client-sd-output-ntlms.txt | tee -a client-sd-output-cracked.txt
```
### STEP 0x04: CORRELATE NTLMS TO HASHES AND SHOW STATS
After step 0x03, copy your client-sd-output-cracked.txt back to your pentest computer and run the sd-util tool again like so:
```
./sd-util.py --correlate --sd-dump client-sd-output.txt --hashcat-pot client-sd-output-cracked.txt --quiet
```
During this step, you can test the client's password policy with the `--string` argument. E.g.: check for the client's name in the passwords. This will also mangle the word using leetspeak many times before giving up!
