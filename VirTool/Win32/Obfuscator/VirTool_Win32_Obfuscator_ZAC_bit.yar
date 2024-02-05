
rule VirTool_Win32_Obfuscator_ZAC_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAC!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5b 89 de 81 eb 90 01 04 83 ee 05 8d 93 90 01 04 b9 90 01 01 00 00 00 bb 90 01 01 00 00 00 30 1a 42 e2 fb 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 00 6a 00 ff 15 90 01 04 ff 15 90 01 04 05 90 01 04 ff 10 c3 90 00 } //01 00 
		$a_03_2 = {6a 40 68 00 30 00 00 68 90 01 02 00 00 6a 00 ff 15 90 01 04 a3 90 01 04 c3 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 35 
	condition:
		any of ($a_*)
 
}