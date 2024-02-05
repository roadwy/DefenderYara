
rule VirTool_Win32_Obfuscator_WV{
	meta:
		description = "VirTool:Win32/Obfuscator.WV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 0f b7 49 16 35 90 01 04 2d 90 00 } //01 00 
		$a_01_1 = {51 ff 50 14 89 45 f8 8b 45 } //01 00 
		$a_01_2 = {ff 70 50 6a 00 ff d1 89 45 fc 8b 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}