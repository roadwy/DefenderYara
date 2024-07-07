
rule Trojan_Win64_CobaltStrike_MN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 c1 ba 01 00 00 00 81 e1 ff 01 00 00 49 89 c8 48 d3 e2 49 c1 f8 06 4a 85 54 c0 10 0f 95 c2 88 d0 48 83 c4 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_MN_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8b 84 24 90 02 04 44 0f b6 04 08 48 63 84 24 90 02 04 33 d2 b9 90 01 04 48 f7 f1 0f b6 44 14 70 41 8b d0 33 d0 90 00 } //2
		$a_03_1 = {03 c1 2b 44 24 58 03 84 24 90 01 04 03 84 24 90 01 04 03 84 24 90 01 04 03 84 24 90 01 04 2b 84 24 90 02 04 48 63 c8 48 8b 84 24 90 02 04 88 14 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}