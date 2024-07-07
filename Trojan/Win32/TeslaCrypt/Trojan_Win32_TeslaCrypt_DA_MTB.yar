
rule Trojan_Win32_TeslaCrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/TeslaCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 84 24 24 01 00 00 89 8c 24 14 01 00 00 8a 9c 24 3d 01 00 00 8b 8c 24 14 01 00 00 32 9c 24 3d 01 00 00 88 9c 24 3d 01 00 00 39 c8 0f 83 } //2
		$a_01_1 = {8a 44 24 4a 8a 4c 24 6c 30 c8 8b 54 24 10 f7 d2 8b 74 24 14 f7 d6 89 74 24 78 89 54 24 7c 24 01 88 44 24 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}