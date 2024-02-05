
rule VirTool_Win32_Obfuscator_AMR{
	meta:
		description = "VirTool:Win32/Obfuscator.AMR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 08 8b 35 90 01 02 40 00 8b 3d 90 01 02 40 00 23 d6 8b 32 66 3b f7 74 08 81 ea 00 00 01 00 eb f1 89 55 f8 8b c2 66 3b d7 0f 85 90 01 04 01 00 5e 8b e5 5d c3 90 00 } //01 00 
		$a_01_1 = {0f b7 48 3c 03 c1 83 c0 78 8b 00 8b 75 f8 56 03 f0 8b 46 20 5f 03 f8 8b 46 14 89 45 ec 89 75 f4 33 c0 89 45 fc 8b c8 8b 75 0c } //02 00 
		$a_03_2 = {ff 4d 5a a0 17 90 09 03 00 00 00 ff 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 b7 
	condition:
		any of ($a_*)
 
}