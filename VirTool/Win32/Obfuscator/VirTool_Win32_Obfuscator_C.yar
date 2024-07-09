
rule VirTool_Win32_Obfuscator_C{
	meta:
		description = "VirTool:Win32/Obfuscator.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 52 b9 1a 00 00 00 0f 31 69 c0 } //1
		$a_01_1 = {3c 2b 74 14 b7 f0 3c 2f 74 0e b7 fc 3c 39 76 08 b7 41 3c 5a } //1
		$a_01_2 = {80 7e 04 3a 75 03 ad ad 4e 80 7e 05 3a 75 04 } //1
		$a_01_3 = {02 ca 8a 0c 39 30 0e 46 ff 4d 10 75 } //1
		$a_03_4 = {81 f1 de c0 ad 0b ff 75 ?? ff 75 ?? 50 51 ff 75 ?? 68 ?? ?? ?? ?? ff 75 ?? ff 35 ?? ?? ?? ?? 58 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}