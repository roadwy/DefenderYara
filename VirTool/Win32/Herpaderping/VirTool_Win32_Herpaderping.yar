
rule VirTool_Win32_Herpaderping{
	meta:
		description = "VirTool:Win32/Herpaderping,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 ec 00 00 00 00 6a 04 6a ff 6a 00 68 ff ff 1f 00 50 ff 15 90 01 04 85 c0 90 01 02 68 b4 77 43 00 90 00 } //01 00 
		$a_03_1 = {c6 45 fc 07 68 00 00 00 01 6a 02 6a 00 6a 00 68 1f 00 0f 00 50 c7 45 e4 00 00 00 00 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_2 = {6a 00 56 8b 35 90 01 04 50 52 57 90 01 02 85 c0 90 01 02 8b 4b 04 ba 61 03 00 00 90 00 } //01 00 
		$a_03_3 = {8b 7d e8 6a 00 57 ff 75 ec 6a 04 6a 00 53 ff 15 90 01 04 8b f0 85 f6 90 00 } //01 00 
		$a_03_4 = {8b 45 e8 8b bd 50 ff ff ff 6a 04 68 00 30 00 00 8b b0 90 01 04 03 30 56 6a 00 57 ff 15 90 01 04 8b d0 89 55 88 85 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}