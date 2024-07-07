
rule VirTool_Win32_Obfuscator_XXX{
	meta:
		description = "VirTool:Win32/Obfuscator.XXX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 03 33 07 f7 d0 03 c1 2d 6a 2b 1e 97 89 06 83 c7 04 42 8b c2 2b 45 18 0f 85 13 00 00 00 33 d2 8b 7d 14 e9 09 00 00 00 5b 5e 5f 8b e5 5d c2 14 00 83 c3 04 83 c6 04 49 75 c6 eb ec } //1
	condition:
		((#a_01_0  & 1)*1) >=100
 
}