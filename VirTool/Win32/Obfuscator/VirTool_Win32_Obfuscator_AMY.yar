
rule VirTool_Win32_Obfuscator_AMY{
	meta:
		description = "VirTool:Win32/Obfuscator.AMY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 8e a0 02 b2 90 04 01 02 e8 e9 } //1
		$a_03_1 = {68 de a9 e0 95 90 04 01 02 e8 e9 } //1
		$a_03_2 = {8b 45 0c 2b 45 10 [05 2b-] ?? ?? ?? ?? 89 45 fc 68 ?? ?? 41 00 6a 90 04 01 03 [?? ?? 41] 00 b9 01 00 00 00 69 d1 ?? ?? 00 00 81 c2 ?? ?? 40 00 ff d2 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}