
rule Ransom_Win32_StopCrypt_PBM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {8d 04 3b 33 44 24 90 01 01 33 c1 81 3d 90 02 08 89 44 24 90 01 01 75 90 00 } //03 00 
		$a_03_1 = {8d 04 3b 33 44 24 90 01 01 33 c1 83 3d 90 02 08 89 44 24 90 01 01 75 90 00 } //01 00 
		$a_01_2 = {2b f0 8b d6 d3 ea } //01 00 
		$a_01_3 = {33 d6 2b fa 81 c3 47 86 c8 61 } //00 00 
	condition:
		any of ($a_*)
 
}