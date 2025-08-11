
rule Trojan_Win32_Fragtor_PGF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c2 89 84 94 2c 01 00 00 42 81 fa 70 02 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Fragtor_PGF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f a3 c8 0f bd c9 8a 06 66 f7 d1 30 d8 88 cd 60 fe c0 88 1c 24 0f 9b c1 d0 c8 8d 8b ?? ?? ?? ?? e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Fragtor_PGF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 06 40 3d 00 9e 00 00 72 e9 } //5
		$a_03_1 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 07 40 3d 00 9e 00 00 75 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}