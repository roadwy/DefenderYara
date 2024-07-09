
rule Trojan_Win64_BazarLoader_QW_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f 94 c0 83 f9 0a 0f 9c c3 30 c3 b8 7a 98 4f 76 41 0f 45 c5 } //10
		$a_02_1 = {0f b6 5d 57 0f b6 4d 56 89 da 30 ca ba ?? ?? ?? ?? 41 0f 45 d4 84 c9 89 d1 41 0f 45 cc 84 db 0f 44 ca eb ac } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win64_BazarLoader_QW_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QW!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 ce 44 29 c6 44 0f af ce 41 83 e1 01 41 83 f9 00 0f 94 c3 80 e3 01 88 9d 06 03 00 00 41 83 fb 0a 0f 9c c3 80 e3 01 88 9d 07 03 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}