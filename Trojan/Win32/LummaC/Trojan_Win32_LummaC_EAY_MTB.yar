
rule Trojan_Win32_LummaC_EAY_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 8c 04 46 e8 43 cc 31 c1 89 4c 24 04 8b 4c 24 04 80 c1 62 88 8c 04 46 e8 43 cc 40 3d be 17 bc 33 } //5
		$a_01_1 = {89 4c 24 08 8b 44 24 08 89 c1 f7 d1 83 e1 1a 25 e5 00 00 00 29 c8 88 84 2c 11 f4 74 a0 45 4b } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}