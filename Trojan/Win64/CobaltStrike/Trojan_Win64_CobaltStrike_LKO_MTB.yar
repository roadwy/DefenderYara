
rule Trojan_Win64_CobaltStrike_LKO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b [0-08] e8 } //1
		$a_03_1 = {72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 6b 6b 2d 65 63 68 6f 31 32 33 2f 61 6f 69 73 6e 64 6f 69 2f [0-1f] 2e 70 6e 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}