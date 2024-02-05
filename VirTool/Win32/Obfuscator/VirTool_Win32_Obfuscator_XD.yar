
rule VirTool_Win32_Obfuscator_XD{
	meta:
		description = "VirTool:Win32/Obfuscator.XD,SIGNATURE_TYPE_PEHSTR_EXT,14 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c6 33 ce 2b c1 03 c7 33 c6 89 45 fc 8b 45 fc 33 c6 2b c7 0f } //01 00 
		$a_03_1 = {8b 92 98 01 00 00 89 75 fc 8b 75 fc 8b 12 8b 76 0c 8a 14 16 80 ea 90 01 01 80 f2 90 01 01 80 fa 90 01 01 0f 90 00 } //01 00 
		$a_03_2 = {f7 d6 23 37 89 32 be 90 01 02 00 00 66 89 75 fc 66 8b 7d fc be 90 01 02 00 00 66 33 fe be 90 01 02 00 00 e9 90 00 } //01 00 
		$a_03_3 = {89 06 8b 75 f8 3b f0 5e 75 08 c6 41 0a 90 01 01 c6 42 08 90 01 01 c6 42 0a 90 01 01 c6 41 02 90 00 } //01 00 
		$a_01_4 = {3d 52 4f 3c 2d } //00 00 
	condition:
		any of ($a_*)
 
}