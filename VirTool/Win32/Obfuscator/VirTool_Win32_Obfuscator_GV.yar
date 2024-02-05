
rule VirTool_Win32_Obfuscator_GV{
	meta:
		description = "VirTool:Win32/Obfuscator.GV,SIGNATURE_TYPE_PEHSTR_EXT,07 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {75 ee d1 e2 03 54 24 10 0f b7 02 c1 e0 02 03 44 24 08 8b 00 03 c3 8b 54 24 30 ff e2 } //01 00 
		$a_03_1 = {89 a2 35 8b 90 09 04 00 c7 44 24 90 00 } //01 00 
		$a_03_2 = {13 04 18 5d 90 09 04 00 c7 44 24 90 00 } //01 00 
		$a_01_3 = {ff 77 50 ff 77 34 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}