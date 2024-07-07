
rule VirTool_Win32_Obfuscator_ARB{
	meta:
		description = "VirTool:Win32/Obfuscator.ARB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 6a 02 0f bf f0 e8 90 01 04 8b 0d 90 01 04 98 3b 45 90 01 01 74 90 01 01 3b f1 76 90 01 01 85 c9 74 90 00 } //1
		$a_01_1 = {b8 31 0c c3 30 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 c2 3b c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}