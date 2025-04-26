
rule VirTool_Win32_Obfuscator_TT{
	meta:
		description = "VirTool:Win32/Obfuscator.TT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 0f b7 49 16 81 f2 ?? ?? ?? ?? 81 c2 } //1
		$a_01_1 = {ff 50 24 81 7d f8 88 13 00 00 76 cc } //1
		$a_01_2 = {ff 70 50 6a 00 ff d1 83 65 f8 00 89 45 fc 8b 45 fc } //1
		$a_03_3 = {eb 0a 80 f1 ?? 80 (c1|e9) ?? 88 08 40 42 8a 0a 80 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}