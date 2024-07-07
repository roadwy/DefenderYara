
rule VirTool_Win32_Obfuscator_BP{
	meta:
		description = "VirTool:Win32/Obfuscator.BP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 c7 04 24 90 01 04 5a 31 f9 66 8b 3a 66 47 66 89 3a 81 ef 90 01 04 66 83 02 01 4f 41 83 c2 01 e8 07 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}