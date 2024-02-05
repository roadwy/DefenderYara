
rule VirTool_Win32_Obfuscator_APR{
	meta:
		description = "VirTool:Win32/Obfuscator.APR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d0 83 c4 0b 44 89 c6 } //01 00 
		$a_01_1 = {68 64 6c 6c 00 } //01 00 
		$a_01_2 = {68 74 33 32 2e } //01 00 
		$a_03_3 = {6a 40 68 00 30 00 00 56 57 ff 15 90 01 04 85 c0 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}