
rule VirTool_Win32_Obfuscator_QL{
	meta:
		description = "VirTool:Win32/Obfuscator.QL,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e9 10 01 08 ff 4d 38 e8 } //01 00 
		$a_01_1 = {83 c1 04 8d 44 04 04 83 f9 10 72 ee a1 2c 51 40 00 } //01 00 
		$a_01_2 = {8b 08 81 f9 6e 54 00 00 76 19 } //01 00 
		$a_01_3 = {40 83 f8 0c 72 e8 8d 45 c4 50 a1 2c 80 40 00 } //01 00 
		$a_01_4 = {6a 0a 8b f0 59 f3 a5 8b 4d 50 01 59 0c ff 45 4c 83 c1 28 89 4d 50 } //00 00 
	condition:
		any of ($a_*)
 
}