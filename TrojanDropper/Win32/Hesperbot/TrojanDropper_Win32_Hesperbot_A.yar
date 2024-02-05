
rule TrojanDropper_Win32_Hesperbot_A{
	meta:
		description = "TrojanDropper:Win32/Hesperbot.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 0c 00 "
		
	strings :
		$a_00_0 = {5f 68 65 73 70 65 72 75 73 5f 63 6f 72 65 5f 65 6e 74 72 79 } //08 00 
		$a_00_1 = {64 72 6f 70 70 65 72 5f 78 38 36 2e 62 69 6e 00 5f 63 6f 72 65 5f 65 6e 74 72 79 40 34 } //08 00 
		$a_01_2 = {66 89 04 4b 41 3b 4d fc 72 c6 33 c0 57 66 89 04 4b c7 45 fc 01 00 00 00 e8 } //08 00 
		$a_01_3 = {8b c7 c1 e0 0b 33 c7 8b 7d f4 89 4d f4 8b 4d fc 89 4d f0 c1 e9 0b 33 c8 c1 e9 08 33 c8 31 4d fc 6a 04 } //02 00 
		$a_00_4 = {49 6e 73 74 61 6c 6c 44 61 74 65 } //02 00 
		$a_00_5 = {44 69 67 69 74 61 6c 50 72 6f 64 75 63 74 49 64 } //02 00 
		$a_00_6 = {4d 61 63 68 69 6e 65 47 75 69 64 } //00 00 
		$a_00_7 = {87 10 00 00 db c9 78 03 50 f3 59 42 30 3e 60 d7 } //ee 24 
	condition:
		any of ($a_*)
 
}