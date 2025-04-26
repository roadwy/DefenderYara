
rule Trojan_Win64_CobaltStrike_GA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 46 74 50 37 55 52 6b 5a 59 4f 48 2a 2b 25 33 26 55 49 48 64 } //1 OFtP7URkZYOH*+%3&UIHd
		$a_01_1 = {6c 65 61 73 65 5c 78 36 34 5c 6f 76 65 72 73 65 65 72 2e 70 64 62 } //1 lease\x64\overseer.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}