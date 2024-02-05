
rule VirTool_Win32_Obfuscator_FH{
	meta:
		description = "VirTool:Win32/Obfuscator.FH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 c2 1c 00 00 c0 } //02 00 
		$a_01_1 = {66 81 7a fe cd 2e } //01 00 
		$a_01_2 = {68 e4 a9 52 09 } //01 00 
		$a_01_3 = {68 3e f6 96 38 } //00 00 
	condition:
		any of ($a_*)
 
}