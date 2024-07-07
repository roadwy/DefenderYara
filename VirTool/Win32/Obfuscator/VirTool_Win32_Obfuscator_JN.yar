
rule VirTool_Win32_Obfuscator_JN{
	meta:
		description = "VirTool:Win32/Obfuscator.JN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ff 3b c1 74 90 01 01 75 90 01 01 c1 90 01 01 20 c1 90 01 01 20 90 02 0c e9 90 02 02 00 00 8b ff 55 8b ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}