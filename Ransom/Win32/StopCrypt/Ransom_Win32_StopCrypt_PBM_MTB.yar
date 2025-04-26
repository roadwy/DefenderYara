
rule Ransom_Win32_StopCrypt_PBM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 04 3b 33 44 24 ?? 33 c1 81 3d [0-08] 89 44 24 ?? 75 } //3
		$a_03_1 = {8d 04 3b 33 44 24 ?? 33 c1 83 3d [0-08] 89 44 24 ?? 75 } //3
		$a_01_2 = {2b f0 8b d6 d3 ea } //1
		$a_01_3 = {33 d6 2b fa 81 c3 47 86 c8 61 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}