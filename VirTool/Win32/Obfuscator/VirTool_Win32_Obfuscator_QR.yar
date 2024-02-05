
rule VirTool_Win32_Obfuscator_QR{
	meta:
		description = "VirTool:Win32/Obfuscator.QR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 fd 46 3b bb } //01 00 
		$a_01_1 = {68 4e fe 58 33 } //01 00 
		$a_01_2 = {0f b7 08 81 e9 4d 5a 00 00 } //01 00 
		$a_01_3 = {66 8f 40 16 90 0f b7 4b 06 } //01 00 
		$a_03_4 = {f7 45 f8 04 00 00 00 0f 84 90 01 04 90 18 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}