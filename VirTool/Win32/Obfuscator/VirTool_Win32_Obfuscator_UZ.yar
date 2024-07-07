
rule VirTool_Win32_Obfuscator_UZ{
	meta:
		description = "VirTool:Win32/Obfuscator.UZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 51 8b 4d 0c 33 d2 f7 f1 59 4e 8a 06 86 04 3a 88 06 58 49 0b c9 75 e3 } //1
		$a_01_1 = {0f b7 08 81 e9 4d 5a 00 00 } //1
		$a_01_2 = {ff 75 08 8f 46 18 ff 75 10 8f 46 1c ff 75 14 8f 46 20 eb 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}