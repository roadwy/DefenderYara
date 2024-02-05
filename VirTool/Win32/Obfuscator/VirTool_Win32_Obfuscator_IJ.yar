
rule VirTool_Win32_Obfuscator_IJ{
	meta:
		description = "VirTool:Win32/Obfuscator.IJ,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c9 c9 64 a1 00 00 00 00 8b e0 } //01 00 
		$a_03_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 90 01 04 33 c0 f7 f0 90 09 07 00 50 51 68 90 00 } //01 00 
		$a_03_2 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 90 01 04 33 c0 f7 f0 90 09 08 00 50 51 52 68 90 00 } //01 00 
		$a_03_3 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 90 01 04 33 c0 f7 f0 90 09 09 00 50 51 52 53 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}