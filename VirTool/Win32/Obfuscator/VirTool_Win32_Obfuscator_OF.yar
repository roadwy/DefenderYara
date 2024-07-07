
rule VirTool_Win32_Obfuscator_OF{
	meta:
		description = "VirTool:Win32/Obfuscator.OF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 50 53 8d 45 ac 8d 5d bc 50 53 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 } //1
		$a_01_1 = {30 14 19 41 3b c8 75 f2 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}