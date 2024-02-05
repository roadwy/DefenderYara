
rule VirTool_Win32_Obfuscator_AGM{
	meta:
		description = "VirTool:Win32/Obfuscator.AGM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c2 8b c7 2b c6 51 5a e2 f6 61 81 90 03 01 01 bd 7d 90 02 04 90 01 02 00 00 74 03 83 ef 04 e2 90 00 } //01 00 
		$a_03_1 = {33 d2 f7 e3 05 90 01 04 a3 90 01 04 ad 33 05 90 01 04 89 90 03 01 01 45 85 90 02 04 a1 90 01 04 bb 90 01 04 33 d2 f7 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}