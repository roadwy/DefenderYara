
rule VirTool_Win32_Obfuscator_JE{
	meta:
		description = "VirTool:Win32/Obfuscator.JE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 13 3b c1 74 90 0a 12 00 fe 7f } //1
		$a_03_1 = {39 45 fc 74 ?? eb 90 0a 11 00 6a 00 e8 } //1
		$a_03_2 = {66 81 3c 18 50 45 (75|0f 85) [0-06] 18 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}