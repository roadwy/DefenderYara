
rule Trojan_Win64_CobaltStrike_VA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 15 53 00 00 00 48 31 c9 e8 } //1
		$a_01_1 = {48 8d 8d e0 04 00 00 48 8b 95 d8 04 00 00 4c 8b c8 48 89 4c 24 30 4c 8b c3 48 8d 8d e8 04 00 00 48 89 4c 24 28 48 8d 4d f0 48 89 4c 24 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}