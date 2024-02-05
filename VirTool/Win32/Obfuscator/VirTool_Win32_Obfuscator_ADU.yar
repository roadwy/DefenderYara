
rule VirTool_Win32_Obfuscator_ADU{
	meta:
		description = "VirTool:Win32/Obfuscator.ADU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 0f b7 44 70 fe 24 0f 8b 55 fc 0f b7 54 5a fe 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 90 01 04 8b 55 fc 0f b7 54 5a fe 66 81 e2 f0 00 0f b6 4d f3 66 03 d1 66 89 54 58 fe 46 8b 45 f8 85 c0 74 05 83 e8 04 8b 00 3b c6 7d 05 be 01 00 00 00 43 4f 75 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}