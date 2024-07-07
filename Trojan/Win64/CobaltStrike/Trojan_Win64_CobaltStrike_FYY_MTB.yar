
rule Trojan_Win64_CobaltStrike_FYY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 58 45 33 c0 33 d2 b9 00 00 04 00 ff 15 6b 20 00 00 } //1
		$a_01_1 = {48 8b 4c 24 30 45 33 c9 ba 01 68 00 00 48 89 44 24 20 ff 15 33 1f 00 00 } //1
		$a_01_2 = {44 8b 05 f9 7e 01 00 48 8b d3 48 8b 0d 8f 88 01 00 e8 91 0e 00 00 48 8b 15 83 88 01 00 45 33 c0 33 c9 ff 15 90 1f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}