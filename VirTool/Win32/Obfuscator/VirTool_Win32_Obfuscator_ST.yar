
rule VirTool_Win32_Obfuscator_ST{
	meta:
		description = "VirTool:Win32/Obfuscator.ST,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 } //01 00 
		$a_03_1 = {74 09 60 6a 01 e8 90 01 04 61 e2 b4 90 00 } //01 00 
		$a_01_2 = {05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 } //01 00 
		$a_03_3 = {eb 00 c7 45 90 01 01 17 de c0 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}