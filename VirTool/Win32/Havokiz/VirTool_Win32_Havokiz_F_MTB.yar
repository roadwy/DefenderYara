
rule VirTool_Win32_Havokiz_F_MTB{
	meta:
		description = "VirTool:Win32/Havokiz.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 0e 00 00 00 52 89 85 4c ff ff ff 89 d8 f3 aa b9 28 00 00 00 90 01 03 f3 aa b9 90 00 } //01 00 
		$a_03_1 = {89 f7 f3 aa c7 04 24 00 00 00 00 ff 15 90 01 04 51 89 c3 90 00 } //01 00 
		$a_01_2 = {89 74 24 08 c7 44 24 04 18 00 00 00 89 04 24 } //00 00 
	condition:
		any of ($a_*)
 
}