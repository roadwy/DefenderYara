
rule VirTool_Win32_Obfuscator_YL{
	meta:
		description = "VirTool:Win32/Obfuscator.YL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 50 58 30 90 01 4c 55 50 58 31 90 01 4c 2e 72 73 72 90 00 } //01 00 
		$a_03_1 = {55 50 58 31 90 01 4c 2e 72 73 72 90 01 04 63 00 00 00 90 00 } //01 00 
		$a_03_2 = {55 50 58 21 90 01 04 0d 09 90 00 } //01 00 
		$a_03_3 = {55 50 58 31 90 01 4c 62 62 73 72 90 01 04 63 00 00 00 90 00 } //01 00 
		$a_03_4 = {55 50 58 31 90 01 4c 62 62 62 62 90 01 04 63 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}