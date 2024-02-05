
rule VirTool_Win32_Obfuscator_EM{
	meta:
		description = "VirTool:Win32/Obfuscator.EM,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8d 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 40 2f 90 02 16 2e 90 03 03 03 65 78 65 6a 70 67 90 00 } //0a 00 
		$a_00_1 = {50 52 0f 31 33 d0 01 55 } //0a 00 
		$a_02_2 = {c7 04 24 40 00 00 00 e8 90 01 02 00 00 90 00 } //0a 00 
		$a_00_3 = {04 24 8b 04 24 } //01 00 
		$a_02_4 = {04 24 c7 04 24 90 01 04 e8 90 01 02 ff ff 8d 90 00 } //01 00 
		$a_02_5 = {24 fc c7 04 24 90 01 04 e8 90 01 02 00 00 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}