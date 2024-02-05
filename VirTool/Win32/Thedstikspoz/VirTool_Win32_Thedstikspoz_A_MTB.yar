
rule VirTool_Win32_Thedstikspoz_A_MTB{
	meta:
		description = "VirTool:Win32/Thedstikspoz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 dc 33 c0 89 45 ec 89 45 e0 8b 45 c0 2b c6 c6 45 fc 04 6a 04 89 45 c0 40 68 00 10 00 00 50 6a 00 ff 15 90 01 04 89 45 c4 85 c0 90 00 } //01 00 
		$a_03_1 = {51 6a 40 a3 90 01 04 0f 10 00 6a 07 50 c6 45 e4 b8 c6 45 e9 ff c6 45 ce e0 c7 45 e5 b0 11 40 00 c7 45 ec 00 00 00 00 c6 45 cf 00 0f 90 01 06 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_2 = {89 75 d4 68 20 15 40 00 6a 00 6a 00 ff 15 90 01 04 89 45 ec 89 45 e0 c6 45 fc 04 89 45 c8 85 c0 90 00 } //01 00 
		$a_03_3 = {68 00 00 00 80 ff 70 04 66 0f 13 45 dc ff 15 90 01 04 8b 90 01 05 89 45 c8 89 4d dc 89 45 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}