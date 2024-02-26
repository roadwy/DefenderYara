
rule VirTool_Win32_Headentesz_A_MTB{
	meta:
		description = "VirTool:Win32/Headentesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 84 e1 41 00 90 01 02 83 ec 90 01 01 89 45 e8 c7 04 24 90 01 04 90 01 05 90 01 02 83 ec 90 01 01 a1 0c 90 00 } //01 00 
		$a_03_1 = {8b 55 f4 89 54 24 90 01 01 c7 44 24 90 01 05 89 44 24 90 01 01 90 01 07 90 01 05 89 45 e4 8b 85 90 00 } //01 00 
		$a_03_2 = {89 45 ec c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 90 01 06 83 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}