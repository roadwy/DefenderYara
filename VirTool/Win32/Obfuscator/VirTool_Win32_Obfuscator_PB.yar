
rule VirTool_Win32_Obfuscator_PB{
	meta:
		description = "VirTool:Win32/Obfuscator.PB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c2 01 3b 15 90 01 04 72 05 ba 00 00 00 00 3b 4d fc 72 02 eb 02 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}