
rule VirTool_Win32_Obfuscator_XM{
	meta:
		description = "VirTool:Win32/Obfuscator.XM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b b5 6c ff ff ff 8b 11 8b 4a 0c 8b 55 d8 8a 14 32 8b 75 ec 32 14 39 8b 7d e8 88 14 01 b8 01 00 00 00 03 c3 70 6e 89 45 a8 e9 } //01 00 
		$a_03_1 = {33 ff 33 f6 b8 ff 00 00 00 3b f0 0f 8f bf 00 00 00 8b 1d 90 01 04 81 fe 00 01 00 00 72 02 ff d3 81 fe 00 01 00 00 72 02 ff d3 8b 55 d8 8b 4d bc 66 0f b6 04 32 66 0f b6 14 31 66 03 c7 90 00 } //01 00 
		$a_00_2 = {3c 00 27 00 7c 00 27 00 3e 00 } //00 00  <'|'>
	condition:
		any of ($a_*)
 
}