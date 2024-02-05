
rule VirTool_Win64_Samdumpz_B_dll{
	meta:
		description = "VirTool:Win64/Samdumpz.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 4d a7 4c 8d 90 01 02 ba 05 00 00 00 ff 90 00 } //01 00 
		$a_03_1 = {4c 8b 45 af 48 8b 4d 9f 4c 8d 90 01 02 4d 8b 40 10 ba ff 07 0f 00 ff 90 01 01 85 c0 0f 90 00 } //01 00 
		$a_03_2 = {33 d2 4c 8b c7 8d 4a 90 01 01 ff 15 90 01 04 4c 8b f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}