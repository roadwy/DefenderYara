
rule VirTool_Win32_Obfuscator_PG{
	meta:
		description = "VirTool:Win32/Obfuscator.PG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {81 a0 00 00 00 03 c7 8b 51 34 8b b1 a4 00 00 00 74 90 01 01 85 f6 74 90 00 01 } //00 31 
		$a_8b_1 = {08 51 e8 90 01 04 8b 55 f4 89 15 44 43 40 00 5f 5e 5d 5b } //83 c4 
		$a_83_2 = {08 ff 25 90 01 04 33 c0 0f 85 90 01 02 ff ff 83 7d f8 00 74 11 90 00 00 00 5d 04 00 00 2f 79 02 80 5c 32 00 } //00 30 
	condition:
		any of ($a_*)
 
}