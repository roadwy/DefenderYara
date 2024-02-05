
rule VirTool_Win32_Obfuscator_AMQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AMQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 89 d7 01 df 89 fa 5f 81 e3 ff ff 0f 00 53 31 04 24 58 ff e0 } //01 00 
		$a_01_1 = {81 04 24 f8 00 00 00 5f 53 89 d3 31 d3 89 da 5b 3b 44 3a 0c 74 2e } //01 00 
		$a_01_2 = {51 52 c7 04 24 01 00 00 00 59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea } //01 00 
		$a_01_3 = {74 2e 51 52 31 d2 33 55 e4 87 d1 5a 36 32 84 29 e4 fe ff ff ff 4d ec ff 45 e4 } //01 00 
		$a_01_4 = {33 50 04 87 d1 5a 51 51 83 04 24 f8 59 d1 e9 50 83 04 24 08 58 eb 24 } //00 00 
	condition:
		any of ($a_*)
 
}