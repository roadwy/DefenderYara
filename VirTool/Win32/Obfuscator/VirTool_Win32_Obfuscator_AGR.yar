
rule VirTool_Win32_Obfuscator_AGR{
	meta:
		description = "VirTool:Win32/Obfuscator.AGR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 7d 08 8b c7 03 40 3c 8b 48 50 0f b7 40 16 c1 e8 0d 83 e0 01 } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 88 0c 02 00 00 89 4d f8 85 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}