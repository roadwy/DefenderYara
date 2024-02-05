
rule VirTool_Win32_Obfuscator_AJN{
	meta:
		description = "VirTool:Win32/Obfuscator.AJN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {74 24 28 fc bf 90 09 07 00 9c 60 68 90 01 0e 03 34 24 90 03 1e 1f 90 03 0f 0b 8a 0e 0f b6 c1 8d 76 01 ff 34 85 90 01 04 c3 ac 0f b6 c0 ff 34 85 90 01 04 c3 90 03 0d 0e 8a 06 0f b6 c0 46 ff 34 85 90 01 04 c3 8a 06 46 0f b6 c0 8d 14 85 90 01 04 ff 22 90 00 01 } //00 2b 
		$a_68_1 = {2f 76 e0 e8 90 01 04 68 5e ce d6 e9 89 45 e4 e8 90 01 04 } //68 f2 
		$a_36_2 = {89 45 e8 e8 90 01 04 8b 7d 08 33 f6 89 45 ec 90 00 00 00 01 00 5d 04 00 00 d5 10 03 80 5c 20 00 00 d6 10 03 80 00 00 01 00 03 00 0a 00 a0 21 5a 62 6f 74 2e 41 4b 56 00 00 01 40 05 82 34 00 04 00 67 16 00 00 66 3f b3 8b 6c a2 e0 4d 35 e3 ab 63 00 a0 02 00 01 20 73 64 37 aa 5d 04 00 00 d6 10 03 80 5c 1e 00 00 d7 10 03 80 00 00 01 00 05 00 08 00 a6 81 4b 79 67 61 } //2e 41 
	condition:
		any of ($a_*)
 
}