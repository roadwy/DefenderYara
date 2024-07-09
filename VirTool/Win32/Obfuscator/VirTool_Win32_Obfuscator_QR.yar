
rule VirTool_Win32_Obfuscator_QR{
	meta:
		description = "VirTool:Win32/Obfuscator.QR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 fd 46 3b bb } //1
		$a_01_1 = {68 4e fe 58 33 } //1
		$a_01_2 = {0f b7 08 81 e9 4d 5a 00 00 } //1
		$a_01_3 = {66 8f 40 16 90 0f b7 4b 06 } //1
		$a_03_4 = {f7 45 f8 04 00 00 00 0f 84 ?? ?? ?? ?? 90 18 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}