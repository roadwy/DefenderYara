
rule Ransom_Win32_StopCrypt_PBO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 33 c2 81 3d [0-0a] 89 44 24 ?? 75 } //1
		$a_03_1 = {2b d8 8b c3 d3 e8 89 9c 24 ?? ?? ?? ?? 03 d3 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? c1 e3 04 03 9c 24 ?? ?? ?? ?? 33 da 81 3d [0-0a] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_PBO_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c1 33 c2 83 3d [0-08] 89 44 24 ?? 75 } //1
		$a_03_1 = {2b f0 8b c6 d3 e8 89 74 24 ?? 03 d6 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c1 e6 04 03 b4 24 ?? ?? ?? ?? 33 f2 81 3d [0-08] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}