
rule VirTool_Win32_Obfuscator_ANX{
	meta:
		description = "VirTool:Win32/Obfuscator.ANX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 0f be c0 0f b7 c0 89 04 24 89 f1 e8 90 01 04 83 ec 04 8a 07 47 84 c0 75 e6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}