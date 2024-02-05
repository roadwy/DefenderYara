
rule VirTool_Win32_Samdumpz_B_dll{
	meta:
		description = "VirTool:Win32/Samdumpz.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 68 ff 0f 0f 00 8d 44 90 01 02 89 5c 24 78 50 6a 00 89 9c 24 84 00 00 00 89 9c 24 88 00 00 00 89 9c 24 8c 00 00 00 c7 44 24 78 18 00 00 00 ff 90 00 } //01 00 
		$a_03_1 = {6a 01 68 00 00 00 02 8d 44 90 01 02 50 6a 00 ff 54 90 01 02 85 c0 0f 88 90 00 } //01 00 
		$a_03_2 = {50 68 ff ff 00 00 8d 44 90 01 02 50 6a 00 8d 44 90 01 02 50 ff 74 24 40 ff 54 90 01 02 89 44 24 54 90 00 } //01 00 
		$a_03_3 = {50 6a 00 68 00 00 10 00 ff 90 01 01 8b f0 89 74 24 5c 85 f6 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}