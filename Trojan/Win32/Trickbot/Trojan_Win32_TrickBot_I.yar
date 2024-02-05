
rule Trojan_Win32_TrickBot_I{
	meta:
		description = "Trojan:Win32/TrickBot.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 83 c0 0c c6 80 90 01 04 00 8b 45 0c 90 02 03 89 45 90 01 01 eb 90 01 01 8b 45 90 01 01 83 c0 0c c6 80 90 01 04 01 90 02 04 83 7d 90 01 02 90 02 07 c7 45 90 01 01 00 00 00 00 c7 45 90 01 01 4c 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_I_2{
	meta:
		description = "Trojan:Win32/TrickBot.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 2b 83 c3 04 33 2f 83 c7 04 89 29 83 c1 04 3b de 0f 43 da 81 ff 90 00 } //01 00 
		$a_00_1 = {b8 04 00 00 00 50 50 50 50 50 50 50 50 6a 02 68 40 10 00 00 e8 } //01 00 
		$a_03_2 = {8a e2 c0 e0 02 c0 e2 04 c0 ec 04 80 e4 03 0a e0 8a 44 90 01 02 88 64 90 01 02 8a f0 c0 e0 06 02 44 90 01 02 c0 ee 02 80 e6 0f 0a f2 88 74 90 01 02 88 44 90 01 02 88 26 90 00 } //01 00 
		$a_00_3 = {a3 3c 9a 87 01 b9 90 5f 01 00 68 c0 27 09 00 68 20 bf 02 00 51 51 50 ff 15 d8 b2 87 01 68 00 08 00 00 } //01 00 
		$a_00_4 = {8d 4c 24 1c ba 20 00 00 00 c7 41 f4 08 02 00 00 c7 41 f8 10 66 00 00 89 51 fc } //00 00 
		$a_00_5 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}