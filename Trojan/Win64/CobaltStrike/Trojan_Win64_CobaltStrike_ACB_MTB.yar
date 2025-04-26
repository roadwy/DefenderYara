
rule Trojan_Win64_CobaltStrike_ACB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 48 8d 5b 01 f7 fd fe c2 32 54 1e ff 41 32 d6 88 53 ff 48 83 ef 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ACB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 c9 8d 04 1a 41 32 44 10 10 49 c1 f9 08 44 31 c8 49 89 c9 48 c1 f9 18 49 c1 f9 10 44 31 c8 31 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ACB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 00 03 00 00 79 c6 85 01 03 00 00 72 c6 85 02 03 00 00 6f c6 85 03 03 00 00 6d c6 85 04 03 00 00 65 c6 85 05 03 00 00 4d c6 85 06 03 00 00 73 c6 85 07 03 00 00 73 c6 85 08 03 00 00 65 c6 85 09 03 00 00 63 c6 85 0a 03 00 00 6f c6 85 0b 03 00 00 72 c6 85 0c 03 00 00 50 c6 85 0d 03 00 00 65 c6 85 0e 03 00 00 74 c6 85 0f 03 00 00 69 c6 85 10 03 00 00 72 c6 85 11 03 00 00 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}