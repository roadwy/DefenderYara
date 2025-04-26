
rule VirTool_Win32_Obfuscator_AGY{
	meta:
		description = "VirTool:Win32/Obfuscator.AGY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 81 c2 ac 95 d5 01 89 55 f0 8b 45 ec 8b 4d f0 } //1
		$a_01_1 = {8b 45 08 05 df 74 01 00 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}