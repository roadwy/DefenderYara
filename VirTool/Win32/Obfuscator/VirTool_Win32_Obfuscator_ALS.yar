
rule VirTool_Win32_Obfuscator_ALS{
	meta:
		description = "VirTool:Win32/Obfuscator.ALS,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 07 35 c6 47 01 5e c6 47 02 74 8b 45 90 01 01 33 d2 90 00 } //01 00 
		$a_03_1 = {8a 1b 3a 5f 02 75 90 01 01 89 b5 90 01 04 83 c1 02 83 c1 14 8b d1 8b 85 90 1b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}