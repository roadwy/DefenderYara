
rule VirTool_Win32_Obfuscator_GY{
	meta:
		description = "VirTool:Win32/Obfuscator.GY,SIGNATURE_TYPE_PEHSTR_EXT,08 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {8d 84 05 f8 fe ff ff } //01 00 
		$a_03_1 = {68 ff ff ff ff 01 90 04 01 08 44 4c 54 5c 64 6c 74 7c 90 04 01 04 24 64 a4 e4 00 90 03 0d 0c 8f 90 04 01 08 c0 c1 c2 c3 c4 c5 c6 c7 90 04 01 08 58 59 5a 5b 5c 5d 5e 5f 90 00 } //01 00 
		$a_03_2 = {68 ff ff ff ff 01 90 04 01 08 04 0c 14 1c 24 2c 34 3c 90 04 01 04 24 64 a4 e4 90 03 0d 0c 8f 90 04 01 08 c0 c1 c2 c3 c4 c5 c6 c7 90 04 01 08 58 59 5a 5b 5c 5d 5e 5f 90 00 } //01 00 
		$a_03_3 = {68 ff ff ff ff 01 90 04 01 08 84 8c 9c 94 ac a4 b4 bc 90 04 01 04 24 64 a4 e4 00 00 00 00 90 03 0d 0c 8f 90 04 01 08 c0 c1 c2 c3 c4 c5 c6 c7 90 04 01 08 58 59 5a 5b 5c 5d 5e 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}