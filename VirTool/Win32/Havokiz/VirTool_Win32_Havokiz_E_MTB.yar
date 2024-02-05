
rule VirTool_Win32_Havokiz_E_MTB{
	meta:
		description = "VirTool:Win32/Havokiz.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 8a 01 48 85 d2 75 } //01 00 
		$a_00_1 = {89 44 24 40 4c 89 44 24 48 44 89 4c 24 34 48 89 54 24 38 89 4c 24 30 e8 } //01 00 
		$a_00_2 = {48 31 db bb 4d 5a 00 00 48 ff c1 3e 66 3b 19 75 } //01 00 
		$a_02_3 = {0f b7 43 14 45 31 c0 48 8d 6c 90 01 02 48 89 ea 90 00 } //01 00 
		$a_00_4 = {45 8b 48 04 48 01 c8 4d 01 c1 49 83 c0 08 } //00 00 
	condition:
		any of ($a_*)
 
}