
rule VirTool_Win32_Obfuscator_AB{
	meta:
		description = "VirTool:Win32/Obfuscator.AB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c7 01 bb 02 00 00 00 e8 f8 00 00 00 73 d5 e8 f1 00 00 00 73 54 33 c0 e8 e8 00 00 00 0f 83 a7 00 00 00 e8 dd 00 00 00 13 c0 e8 d6 00 00 00 13 c0 e8 cf 00 00 00 13 c0 e8 c8 00 00 00 13 c0 74 15 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule VirTool_Win32_Obfuscator_AB_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c7 01 bb 02 00 00 00 e8 1f 01 00 00 73 c9 e8 18 01 00 00 73 60 33 c0 e8 0f 01 00 00 0f 83 c2 00 00 00 e8 04 01 00 00 13 c0 e8 fd 00 00 00 13 c0 e8 f6 00 00 00 13 c0 e8 ef 00 00 00 13 c0 74 21 eb 04 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}