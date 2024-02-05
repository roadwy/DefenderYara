
rule VirTool_Win32_Obfuscator_AHG{
	meta:
		description = "VirTool:Win32/Obfuscator.AHG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 0f be 11 83 fa 41 90 01 02 8b 45 08 0f be 08 83 f9 5a 90 01 02 8b 55 08 0f be 02 83 e8 34 99 b9 1a 00 00 00 f7 f9 83 c2 41 8b 45 08 88 10 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 68 6a 8e 08 20 6a 01 e8 90 01 04 83 c4 08 89 90 01 02 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}