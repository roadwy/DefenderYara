
rule Trojan_Win64_CobaltStrike_CMP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 85 a0 09 c1 89 ca 8b 85 a4 01 00 00 48 98 48 8d 48 02 48 8b 85 98 01 00 00 48 01 c8 88 10 83 85 a4 01 00 00 03 83 85 a8 01 00 00 04 8b 85 a0 01 00 00 83 e8 02 39 85 a8 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CMP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 44 24 24 83 f8 41 7c 17 0f b7 44 24 24 83 f8 5a 7f 0d 0f b7 44 24 24 83 c0 20 66 89 44 24 24 0f b7 44 24 28 83 f8 41 7c 17 0f b7 44 24 28 83 f8 5a 7f 0d 0f b7 44 24 28 83 c0 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}