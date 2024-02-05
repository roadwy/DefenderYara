
rule VirTool_Win64_Samdumpz_A_dll{
	meta:
		description = "VirTool:Win64/Samdumpz.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 57 c0 0f 57 c9 4c 8d 90 01 02 48 8d 90 01 02 41 b8 ff 0f 0f 00 33 c9 89 7d ff c7 45 e7 30 00 00 00 f3 0f 7f 45 ef f3 0f 7f 4d 07 ff 90 00 } //01 00 
		$a_03_1 = {48 8b 4d 87 48 8d 90 01 02 4c 8d 90 01 02 48 89 44 24 28 48 8d 90 01 02 45 33 c0 c7 44 24 20 ff ff 00 00 ff 90 01 02 89 45 6f 90 00 } //01 00 
		$a_03_2 = {48 8b 4c 24 38 4c 8d 90 01 02 ba 12 00 00 00 41 ff 90 01 01 85 c0 0f 88 90 00 } //01 00 
		$a_03_3 = {33 d2 4c 8b c6 8d 4a 90 01 01 ff 15 90 01 04 4c 8b f8 48 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}