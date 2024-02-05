
rule VirTool_Win32_Obfuscator_XS{
	meta:
		description = "VirTool:Win32/Obfuscator.XS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 8a 47 01 47 84 c0 75 f8 a0 90 01 04 8b 0d 90 01 04 04 30 a2 90 01 04 34 45 89 0f a2 90 00 } //01 00 
		$a_03_1 = {8b 48 14 8b 78 10 a0 90 01 04 8b 35 90 01 04 68 90 01 04 6a 00 6a 00 04 30 68 90 01 04 03 cf a2 90 01 04 6a 00 03 f1 34 44 6a 00 89 35 90 01 04 a2 90 00 } //01 00 
		$a_03_2 = {8a 17 32 d0 46 81 fe 90 01 04 88 17 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}