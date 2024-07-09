
rule VirTool_Win32_Obfuscator_GG{
	meta:
		description = "VirTool:Win32/Obfuscator.GG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e c0 0f 6e ca 0f 73 f0 [0-02] 0f ef c1 0f 6e cf 0f 7e ce ad 0f 6e d0 ad 0f 6e d8 0f 73 f2 [0-02] 0f ef d3 0f ef d0 0f 7e d0 ab 0f 73 d2 [0-02] 0f 7e d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}