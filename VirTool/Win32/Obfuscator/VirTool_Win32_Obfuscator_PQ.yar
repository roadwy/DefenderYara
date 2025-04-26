
rule VirTool_Win32_Obfuscator_PQ{
	meta:
		description = "VirTool:Win32/Obfuscator.PQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d9 fe d9 fb d9 fa d9 cd } //1
		$a_01_1 = {40 00 0f 18 86 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}