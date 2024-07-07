
rule Trojan_Win64_CobaltStrike_DECI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DECI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 73 20 8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a } //1
		$a_01_1 = {48 8b d3 48 8b ce 48 2b c3 48 d1 f8 4c 8b c0 e8 7c 10 00 00 48 8b ce ff 15 5b 16 00 00 48 8b f0 48 8b cb ff 15 4f 16 00 00 48 8b d8 0f b7 38 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}