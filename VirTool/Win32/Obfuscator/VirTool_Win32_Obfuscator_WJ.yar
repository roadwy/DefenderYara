
rule VirTool_Win32_Obfuscator_WJ{
	meta:
		description = "VirTool:Win32/Obfuscator.WJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 17 32 d0 46 81 fe 00 35 0c 00 88 17 7c 90 14 a1 90 01 04 8d 3c 30 90 13 56 8b 35 90 01 04 ff d6 ff d6 ff d6 ff d6 ff d6 a1 90 00 } //01 00 
		$a_03_1 = {33 d2 8b c1 f7 f5 8b 44 24 14 0f be 14 02 33 c0 8a 81 90 02 10 03 d0 81 e2 ff 00 00 00 89 15 90 01 04 ff 90 01 01 8b 0d 90 01 04 8a 99 90 01 04 ff 90 01 01 8b 90 01 05 90 03 04 04 a1 90 01 04 8b 90 01 05 8a 90 01 05 88 90 01 05 90 03 06 07 40 3d 00 01 00 00 41 81 f9 00 01 00 00 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}