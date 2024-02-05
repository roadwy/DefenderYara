
rule Ransom_Win32_StopCrypt_SM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 4d fc 89 4d 90 01 01 8b 45 90 01 01 01 05 90 00 } //01 00 
		$a_03_1 = {8b c3 c1 e0 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_SM_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c5 d3 e0 8b cd c1 e9 90 01 01 03 4c 24 90 01 01 03 44 24 90 01 01 89 35 90 01 04 33 c1 8b 4c 24 90 01 01 03 cd 33 c1 29 44 24 90 01 01 81 3d 90 01 06 00 00 75 90 00 } //01 00 
		$a_02_1 = {53 8b 19 55 8b 69 04 56 33 f6 81 3d 90 01 06 00 00 57 8b fa 89 4c 24 90 01 01 89 5c 24 90 01 01 75 90 00 } //01 00 
		$a_02_2 = {56 57 8b f1 8b fa 81 3d 90 01 06 00 00 75 90 01 01 6a 00 ff 15 90 01 04 8b 54 24 90 01 01 8b ce e8 90 01 04 83 c6 08 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}