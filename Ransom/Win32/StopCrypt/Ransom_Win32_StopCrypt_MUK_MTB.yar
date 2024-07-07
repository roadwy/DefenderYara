
rule Ransom_Win32_StopCrypt_MUK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 90 02 04 8b 44 24 1c 29 44 24 14 8b 44 24 14 c1 e0 90 02 01 89 44 24 10 8b 44 24 30 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 81 3d 90 02 06 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_MUK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 5d f4 89 75 f8 25 90 02 04 81 6d f8 90 02 04 81 45 f8 90 02 04 8b 4d dc 8b c3 c1 e8 90 02 01 89 45 f4 8d 45 f4 90 00 } //1
		$a_03_1 = {8b 45 fc 8b 4d f0 03 c7 89 45 e8 8b c7 d3 e8 8b 4d d4 c7 05 90 02 08 89 45 f4 8d 45 f4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}