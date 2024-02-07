
rule Backdoor_Win32_Drixed_E{
	meta:
		description = "Backdoor:Win32/Drixed.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 e0 93 04 00 85 d2 74 05 b8 } //01 00 
		$a_01_1 = {7e 02 8b f0 85 db 7e 08 8b c8 2b ce 3b d9 7e 04 2b c6 8b d8 85 db 7f 0e } //01 00 
		$a_01_2 = {50 ff d6 89 45 08 39 7d 08 75 24 8b 45 fc 39 78 18 74 08 8b 40 18 8b 40 04 89 03 68 d1 00 00 00 } //01 00 
		$a_01_3 = {74 0d 6a 10 8d 4d ec 51 ff 36 ff d0 89 45 fc 83 7d fc 00 74 13 c7 } //01 00 
		$a_01_4 = {eb 02 33 c0 89 43 04 6a 7c 8d 45 dc 50 6a 0e 8d 45 f0 e8 } //02 00 
		$a_01_5 = {32 5c 0d f4 41 88 5c 0d eb 83 f9 08 72 ef 8b 5d 08 33 ff 8a 4c 3d ec 84 c9 75 10 ff 45 fc 39 5d fc } //01 00 
		$a_01_6 = {33 c0 66 8b 54 05 f8 66 33 17 83 c0 02 66 89 54 05 ee 83 c7 02 83 f8 08 72 e8 33 d2 0f } //01 00 
		$a_01_7 = {80 79 05 61 75 25 80 79 04 74 75 1f 80 79 03 61 75 19 80 79 02 64 75 13 80 79 01 73 } //00 00 
		$a_00_8 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}