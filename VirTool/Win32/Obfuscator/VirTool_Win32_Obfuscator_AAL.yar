
rule VirTool_Win32_Obfuscator_AAL{
	meta:
		description = "VirTool:Win32/Obfuscator.AAL,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 45 a4 81 7d a4 90 01 01 00 10 80 75 0e c7 45 a4 00 00 00 00 c7 45 e8 90 01 04 83 7d d0 00 74 90 00 } //05 00 
		$a_01_1 = {8a 08 88 0a 8b 55 10 03 55 f8 0f b6 02 8b 4d 08 03 4d fc 0f b6 11 03 d0 8b 45 08 03 45 fc 88 10 83 7d f8 05 75 } //00 00 
	condition:
		any of ($a_*)
 
}