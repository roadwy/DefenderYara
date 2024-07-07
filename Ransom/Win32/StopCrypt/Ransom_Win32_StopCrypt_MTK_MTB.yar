
rule Ransom_Win32_StopCrypt_MTK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2 } //1
		$a_03_1 = {55 8b ec 8b 45 0c c1 e0 90 02 01 8b 4d 08 89 01 5d c2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_MTK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 18 c7 05 90 02 08 33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 90 02 04 8b 44 24 1c 29 44 24 14 8b 4c 24 14 c1 e1 90 02 01 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 81 3d 90 02 06 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}