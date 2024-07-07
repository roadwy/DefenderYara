
rule Trojan_Win64_BazarLoader_MZK_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 ff c2 c1 c2 90 02 01 4d 03 d1 0f be c9 33 d1 41 ff c0 41 8a 0a 84 c9 75 90 00 } //1
		$a_03_1 = {45 33 c9 48 03 cf 45 33 c0 33 d2 e8 90 02 04 41 3b c7 74 90 02 01 48 83 c5 90 02 01 48 83 c6 90 02 01 41 ff c6 44 3b 73 90 02 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}