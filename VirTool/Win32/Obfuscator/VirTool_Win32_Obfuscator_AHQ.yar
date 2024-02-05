
rule VirTool_Win32_Obfuscator_AHQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AHQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 11 83 fa 55 74 1c 8b 45 e8 0f b6 08 83 f9 6a 74 11 8b 55 e8 0f b6 02 3d ff 00 00 00 74 04 33 c0 eb 29 83 7d 08 03 } //00 00 
	condition:
		any of ($a_*)
 
}