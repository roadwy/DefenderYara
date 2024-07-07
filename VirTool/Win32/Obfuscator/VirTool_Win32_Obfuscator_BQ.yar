
rule VirTool_Win32_Obfuscator_BQ{
	meta:
		description = "VirTool:Win32/Obfuscator.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 39 66 83 c7 01 66 89 39 01 d7 50 29 c2 5a 66 8b 11 66 83 c2 01 66 89 11 81 e3 90 01 04 e8 11 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}