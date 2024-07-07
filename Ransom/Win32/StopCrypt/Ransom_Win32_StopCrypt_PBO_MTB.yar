
rule Ransom_Win32_StopCrypt_PBO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 33 c2 81 3d 90 02 0a 89 44 24 90 01 01 75 90 00 } //1
		$a_03_1 = {2b d8 8b c3 d3 e8 89 9c 24 90 01 04 03 d3 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 c1 e3 04 03 9c 24 90 01 04 33 da 81 3d 90 02 0a 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_PBO_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 33 c2 83 3d 90 02 08 89 44 24 90 01 01 75 90 00 } //1
		$a_03_1 = {2b f0 8b c6 d3 e8 89 74 24 90 01 01 03 d6 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 c1 e6 04 03 b4 24 90 01 04 33 f2 81 3d 90 02 08 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}