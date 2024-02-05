
rule VirTool_Win32_Obfuscator_HB{
	meta:
		description = "VirTool:Win32/Obfuscator.HB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc c9 89 44 24 1c 61 9d ff e0 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 18 8b 40 0c 83 f8 02 } //01 00 
		$a_01_2 = {2e 64 6c 6c 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}