
rule VirTool_Win32_Obfuscator_AGB{
	meta:
		description = "VirTool:Win32/Obfuscator.AGB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 14 f3 bb 51 89 02 83 c7 04 41 8b c1 2b 45 18 0f 85 05 00 00 00 e9 0b 00 00 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}