
rule VirTool_Win32_Obfuscator_RO{
	meta:
		description = "VirTool:Win32/Obfuscator.RO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c6 33 ce 33 de 8d 84 18 ?? ?? 00 00 33 d2 03 cf f7 f1 6a 7f c1 e2 03 89 55 f8 8b 45 f8 } //1
		$a_01_1 = {8b 45 f4 33 c6 2b d8 2b df 33 de 81 fb fe cf ff ff } //1
		$a_03_2 = {8d 45 ec c7 45 ec ?? ?? ?? 00 89 45 d4 33 f6 b9 00 31 00 00 8b 55 ec 8b c6 83 e0 03 8d } //1
		$a_01_3 = {8b 38 2b d1 0b d7 89 10 33 d2 8b 7d ec 8b c2 83 e0 03 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}