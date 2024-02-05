
rule VirTool_Win32_Obfuscator_AIY{
	meta:
		description = "VirTool:Win32/Obfuscator.AIY,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 32 d8 88 1c 11 a1 90 01 04 40 83 f8 10 a3 90 01 04 75 90 01 01 33 c0 a3 90 01 04 8b 0d 90 01 04 c7 05 90 01 04 00 00 00 00 41 4e 89 0d 90 01 04 75 90 01 01 5e 5b 90 00 } //01 00 
		$a_03_1 = {64 8b 1d 18 00 00 00 89 1d 90 02 14 8b 90 01 01 30 90 01 05 8b 90 01 01 0c a3 90 01 04 8b 90 01 01 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}