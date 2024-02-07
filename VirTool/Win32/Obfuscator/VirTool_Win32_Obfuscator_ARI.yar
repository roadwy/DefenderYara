
rule VirTool_Win32_Obfuscator_ARI{
	meta:
		description = "VirTool:Win32/Obfuscator.ARI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a c3 02 c1 8a d1 8b 4d 10 2a d1 04 04 f6 ea 8b 55 08 f6 e9 32 04 13 } //01 00 
		$a_03_1 = {74 0c 8b 0d 90 01 04 89 0d 90 01 04 6a 00 57 68 23 02 00 00 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}