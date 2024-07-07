
rule VirTool_Win32_Obfuscator_KG{
	meta:
		description = "VirTool:Win32/Obfuscator.KG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 74 14 8d 05 90 01 04 8b 00 3b 05 90 01 04 75 02 eb 02 eb e7 90 00 } //1
		$a_03_1 = {33 c0 40 74 11 a1 90 01 04 3b 05 90 01 04 75 02 eb 02 eb ea 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}