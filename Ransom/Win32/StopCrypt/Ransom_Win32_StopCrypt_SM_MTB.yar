
rule Ransom_Win32_StopCrypt_SM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 4d fc 89 4d ?? 8b 45 ?? 01 05 } //1
		$a_03_1 = {8b c3 c1 e0 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_SM_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b c5 d3 e0 8b cd c1 e9 ?? 03 4c 24 ?? 03 44 24 ?? 89 35 ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cd 33 c1 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 } //1
		$a_02_1 = {53 8b 19 55 8b 69 04 56 33 f6 81 3d ?? ?? ?? ?? ?? ?? 00 00 57 8b fa 89 4c 24 ?? 89 5c 24 ?? 75 } //1
		$a_02_2 = {56 57 8b f1 8b fa 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b ce e8 ?? ?? ?? ?? 83 c6 08 4f 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}