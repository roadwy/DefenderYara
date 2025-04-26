
rule VirTool_Win32_Obfuscator_AJA{
	meta:
		description = "VirTool:Win32/Obfuscator.AJA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 32 01 90 } //1
		$a_01_1 = {8b 7d fc 90 ff e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}