
rule VirTool_Win32_Obfuscator_PU{
	meta:
		description = "VirTool:Win32/Obfuscator.PU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {87 ec 8d 6d fc 89 65 00 8d 65 } //1
		$a_03_1 = {81 14 24 89 0a 00 00 [0-04] ba fd a5 17 [0-04] 81 14 24 5e 34 9a e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}