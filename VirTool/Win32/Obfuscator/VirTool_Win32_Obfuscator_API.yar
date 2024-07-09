
rule VirTool_Win32_Obfuscator_API{
	meta:
		description = "VirTool:Win32/Obfuscator.API,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c7 04 83 e9 04 83 f9 00 90 13 90 13 31 } //1
		$a_03_1 = {83 c7 04 83 e9 04 90 13 8b 02 83 c2 04 89 07 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_API_2{
	meta:
		description = "VirTool:Win32/Obfuscator.API,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 83 c4 f0 b8 3b 00 00 00 [0-10] 93 e8 ?? ?? ff ff e8 ?? ?? ff ff a3 ?? ?? ?? ?? e8 ?? ?? ff ff ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff } //1
		$a_03_1 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 57 74 05 e8 } //1
		$a_03_2 = {e8 00 00 00 00 5b 89 de 81 eb ?? ?? ?? ?? 83 ee 05 8d 93 ?? ?? ?? ?? b9 ae 00 00 00 80 32 ?? 42 e2 fa } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}