
rule VirTool_Win32_Obfuscator_QN{
	meta:
		description = "VirTool:Win32/Obfuscator.QN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_13_0 = {00 00 00 00 5b 32 db 81 e3 90 01 01 f0 ff ff 89 5d fc 81 c3 00 0c 00 00 83 eb 04 8b 4d 08 89 0b 8b 45 fc 5b c9 c3 90 00 01 } //00 17 
		$a_33_1 = {64 8b 40 30 56 8b 40 0c 8b 70 1c ad 8b 40 08 5e c3 } //8b 4c 
		$a_04_2 = {01 00 1e 13 66 49 81 c1 b5 a5 00 00 66 49 74 07 2d 00 10 00 00 eb 90 01 01 25 90 01 01 f0 ff ff 90 00 01 00 } //17 01 
		$a_e8_3 = {87 04 24 50 68 00 40 00 00 6a 00 ff 74 24 f8 51 ff 64 24 ec 00 00 78 bf 00 00 0a 00 03 00 06 00 00 01 00 27 01 55 8b ec f6 40 0c 40 74 06 83 78 08 00 74 1a 50 ff 75 08 e8 e3 26 00 00 59 59 b9 ff ff 00 00 66 3b c1 75 05 83 0e ff 01 00 1f 01 eb 0c 8d 45 e0 50 53 e8 3e 00 00 00 59 59 ff 4d e4 78 07 8b 45 e0 88 18 eb 0c 8d 45 e0 50 53 01 00 2b 01 55 8b ec 83 ec 14 8b 45 0c 89 45 f4 c7 45 f8 00 00 00 00 33 c9 89 4d fc c7 45 f0 00 00 00 00 c7 45 ec 8b 02 00 00 68 00 30 00 00 01 00 09 01 ff ff eb 02 eb 9a c2 0f 00 01 00 19 01 30 39 2d 30 61 2d 73 30 39 61 2d 73 64 39 61 39 2d 73 } //64 2d 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_QN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.QN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec f6 40 0c 40 74 06 83 78 08 00 74 1a 50 ff 75 08 e8 e3 26 00 00 59 59 b9 ff ff 00 00 66 3b c1 75 05 83 0e ff } //01 00 
		$a_01_1 = {eb 0c 8d 45 e0 50 53 e8 3e 00 00 00 59 59 ff 4d e4 78 07 8b 45 e0 88 18 eb 0c 8d 45 e0 50 53 } //01 00 
		$a_01_2 = {55 8b ec 83 ec 14 8b 45 0c 89 45 f4 c7 45 f8 00 00 00 00 33 c9 89 4d fc c7 45 f0 00 00 00 00 c7 45 ec 8b 02 00 00 68 00 30 00 00 } //01 00 
		$a_01_3 = {ff ff eb 02 eb 9a c2 0f 00 } //01 00 
		$a_01_4 = {30 39 2d 30 61 2d 73 30 39 61 2d 73 64 39 61 39 2d 73 64 2d 61 73 2d 64 2d } //01 00  09-0a-s09a-sd9a9-sd-as-d-
		$a_01_5 = {30 39 2d 30 61 2d 73 34 33 35 35 } //00 00  09-0a-s4355
	condition:
		any of ($a_*)
 
}