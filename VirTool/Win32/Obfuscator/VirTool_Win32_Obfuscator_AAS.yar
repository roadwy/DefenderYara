
rule VirTool_Win32_Obfuscator_AAS{
	meta:
		description = "VirTool:Win32/Obfuscator.AAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0e 85 fb 30 17 85 fb 49 85 fb 47 85 fb eb ee } //1
		$a_01_1 = {b8 fb 81 ec bf f7 e1 89 d0 c1 e8 0e 89 45 08 8b 45 08 69 c0 5e 55 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}