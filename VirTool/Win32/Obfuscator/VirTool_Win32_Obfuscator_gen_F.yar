
rule VirTool_Win32_Obfuscator_gen_F{
	meta:
		description = "VirTool:Win32/Obfuscator.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 45 fc 55 bb cf 54 81 7d ec c1 f2 b9 82 } //1
		$a_03_1 = {89 45 f0 ff 75 f0 81 45 fc b7 f1 bb de ff 15 90 01 03 00 89 45 f0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}