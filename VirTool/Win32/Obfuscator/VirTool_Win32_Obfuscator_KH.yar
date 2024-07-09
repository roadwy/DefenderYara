
rule VirTool_Win32_Obfuscator_KH{
	meta:
		description = "VirTool:Win32/Obfuscator.KH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 51 8b 4d 0c 33 d2 f7 f1 59 4e 8a 06 86 04 3a 88 06 58 49 0b c9 75 e3 } //1
		$a_03_1 = {03 5b 3c 8b 4b 54 81 c3 f8 00 00 00 (8b 5b 14|ff 73 14 [0)-05] 5b 0b db 75 02 } //1
		$a_03_2 = {68 c8 12 11 97 50 e8 ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}