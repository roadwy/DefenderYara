
rule VirTool_Win32_Obfuscator_ABK{
	meta:
		description = "VirTool:Win32/Obfuscator.ABK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7d 08 00 74 07 b8 90 01 01 90 04 01 03 21 22 23 00 10 eb 05 b8 90 01 01 90 04 01 03 21 22 23 00 10 8b e5 5d c2 04 00 90 00 } //01 00 
		$a_01_1 = {c7 45 fb 00 00 00 00 0f b6 4d 10 83 f9 00 75 02 eb 4e eb 19 8b 4d fb } //00 00 
	condition:
		any of ($a_*)
 
}