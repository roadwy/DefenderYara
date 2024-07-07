
rule VirTool_Win32_Obfuscator_ACQ{
	meta:
		description = "VirTool:Win32/Obfuscator.ACQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c6 2d db ae 53 72 89 45 f8 8b 45 fc 8b 4d f8 33 c7 03 c3 3b c8 0f 85 1f 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}