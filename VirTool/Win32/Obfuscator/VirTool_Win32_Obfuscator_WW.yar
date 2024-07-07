
rule VirTool_Win32_Obfuscator_WW{
	meta:
		description = "VirTool:Win32/Obfuscator.WW,SIGNATURE_TYPE_PEHSTR_EXT,14 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 0c 3a 02 0f 85 51 00 00 00 8b 45 f8 8b 55 0c 0f be 12 33 c1 2b c6 3b d0 0f } //1
		$a_03_1 = {8b 45 f0 33 c3 be 90 01 01 da 9a 78 2b c6 89 45 f8 8b 45 f0 83 65 b0 00 90 00 } //1
		$a_03_2 = {89 45 ec 8b 45 dc 8b 75 08 33 c3 bf 90 01 01 da 9a 78 2b c7 8d 90 00 } //1
		$a_01_3 = {68 d3 ef f2 0d ff 75 08 8d 45 f4 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}