
rule Trojan_Win64_SlickPlummet_A_dha{
	meta:
		description = "Trojan:Win64/SlickPlummet.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 73 3a 25 64 3a 25 73 28 29 3a 20 5b 2b 5d 20 4f 76 65 72 77 72 69 74 69 6e 67 20 22 25 73 } //1 %s:%d:%s(): [+] Overwriting "%s
		$a_01_1 = {25 73 3a 25 64 3a 25 73 28 29 3a 20 5b 2b 5d 20 53 74 61 72 74 69 6e 67 20 52 61 77 49 6f 20 64 69 73 6b 20 64 72 69 76 65 72 20 73 65 72 76 69 63 65 2e 2e } //1 %s:%d:%s(): [+] Starting RawIo disk driver service..
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}