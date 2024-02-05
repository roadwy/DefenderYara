
rule VirTool_Win32_Obfuscator_AQQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AQQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {23 f6 51 56 a9 f4 ee 21 37 5e 59 53 81 f5 00 00 00 00 5b b9 90 01 03 00 a9 0a b3 50 46 7e 02 22 ed 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_AQQ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AQQ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 14 08 a1 98 0e 42 00 8b f3 0f af f7 88 54 24 0b 99 8d 4e 02 f7 f9 03 05 9c 0e 42 00 3b 05 b0 0e 42 00 7e 06 ff 0d 9c 0e 42 00 83 c3 03 0f af df 03 de 8a c3 32 44 24 0b 8d 54 24 20 88 44 24 18 } //01 00 
		$a_01_1 = {8b 54 24 0c 88 04 10 8b c3 99 2b c2 d1 f8 8b ce 2b cf 0f af c8 8b 44 24 14 8d 50 04 0f af ca 03 ce 0f af cb 03 cf 03 c1 89 44 24 14 8b 44 24 0c 40 3b 45 0c 89 44 24 0c 0f 8c 3f ff ff ff } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}