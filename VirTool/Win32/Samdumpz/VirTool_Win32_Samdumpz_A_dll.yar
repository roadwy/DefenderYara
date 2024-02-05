
rule VirTool_Win32_Samdumpz_A_dll{
	meta:
		description = "VirTool:Win32/Samdumpz.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 05 ff 74 24 40 ff 15 90 01 04 33 c9 90 00 } //01 00 
		$a_03_1 = {50 68 ff ff 00 00 8d 44 90 01 02 50 6a 00 8d 44 90 01 02 50 ff 74 24 44 ff 54 24 28 89 44 24 64 90 00 } //01 00 
		$a_03_2 = {50 6a 00 68 00 00 10 00 ff 90 01 01 8b f8 90 00 } //01 00 
		$a_03_3 = {50 6a 12 ff 74 24 2c ff 54 90 01 02 85 c0 0f 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}