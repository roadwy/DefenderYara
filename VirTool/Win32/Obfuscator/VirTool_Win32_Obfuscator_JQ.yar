
rule VirTool_Win32_Obfuscator_JQ{
	meta:
		description = "VirTool:Win32/Obfuscator.JQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 05 f8 02 fe 7f 35 55 00 00 c0 60 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}