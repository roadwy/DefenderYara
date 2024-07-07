
rule VirTool_Win32_Obfuscator_OQ{
	meta:
		description = "VirTool:Win32/Obfuscator.OQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 5e 8b 24 24 8b ad 90 01 03 00 8d bd 90 01 03 00 8a 06 8b 5e 01 88 07 89 5f 01 c6 06 e9 8d bd 90 01 03 00 2b fe 83 ef 05 89 7e 01 89 b5 90 01 03 00 8b b5 90 01 03 00 83 c6 02 56 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}