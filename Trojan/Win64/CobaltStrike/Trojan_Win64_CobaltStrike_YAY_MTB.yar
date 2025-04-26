
rule Trojan_Win64_CobaltStrike_YAY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 31 34 39 2e 32 38 2e 32 32 32 2e 32 34 34 3a 38 30 30 30 2f [0-0a] 2e 65 78 65 } //1
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 } //1 Download
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}