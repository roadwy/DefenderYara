
rule VirTool_Win32_Obfuscator_AAY{
	meta:
		description = "VirTool:Win32/Obfuscator.AAY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {e1 05 be c7 45 90 01 02 e1 05 be ff 15 90 01 04 6a 90 01 01 ff 15 90 01 04 85 c0 0f 8f 90 09 04 00 c7 45 90 00 } //01 00 
		$a_03_1 = {e2 05 be 8b 45 90 01 01 8b 4d 90 01 01 0f af c1 89 45 90 01 01 8d 45 90 01 01 56 89 45 90 01 01 be 90 01 01 68 62 7b e9 90 09 04 00 c7 45 90 00 } //01 00 
		$a_03_2 = {c7 45 b8 3b e1 05 be 90 02 0c c7 45 f0 00 00 00 00 90 02 18 c7 45 b8 3a e1 05 be 90 00 } //01 00 
		$a_03_3 = {3d db e3 05 be 90 02 0c 0f 85 90 16 90 02 0c 81 7d d8 2a e1 05 be 90 02 0c 0f 85 90 16 90 02 0c 8b 45 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}