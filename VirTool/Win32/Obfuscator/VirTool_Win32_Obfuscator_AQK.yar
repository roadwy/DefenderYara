
rule VirTool_Win32_Obfuscator_AQK{
	meta:
		description = "VirTool:Win32/Obfuscator.AQK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 54 5f 41 ab 51 58 6a 05 48 ab 5a 4a 8b 06 03 f2 89 07 03 fa e2 f6 90 09 06 00 41 8d 05 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}