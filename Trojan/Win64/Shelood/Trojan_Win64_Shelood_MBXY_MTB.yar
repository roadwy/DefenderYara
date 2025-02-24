
rule Trojan_Win64_Shelood_MBXY_MTB{
	meta:
		description = "Trojan:Win64/Shelood.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 34 11 33 48 ff c1 48 8b 05 ?? ?? 00 00 48 8b 15 ?? ?? 00 00 48 2b c2 48 3b c8 72 } //1
		$a_01_1 = {48 89 44 24 28 c6 44 24 60 7e c6 44 24 61 69 c6 44 24 62 a3 c6 44 24 63 33 c6 44 24 64 30 c6 44 24 65 33 c6 44 24 66 33 c6 44 24 67 33 c6 44 24 68 37 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}