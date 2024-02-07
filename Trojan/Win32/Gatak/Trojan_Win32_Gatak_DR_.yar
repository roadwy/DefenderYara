
rule Trojan_Win32_Gatak_DR_{
	meta:
		description = "Trojan:Win32/Gatak.DR!!Gatak.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c } //01 00 
		$a_01_1 = {74 06 81 f6 20 83 b8 ed d1 ea 4f 75 eb } //01 00 
		$a_01_2 = {77 03 80 c2 20 38 54 35 ec 75 0f 46 41 41 83 fe 09 72 e3 } //01 00 
		$a_03_3 = {68 eb 2f 76 e0 e8 90 01 02 ff ff 68 5e ce d6 e9 89 45 e8 e8 28 fb ff ff 68 f2 79 36 18 89 45 ec e8 90 01 02 ff ff 90 00 } //01 00 
		$a_01_4 = {e8 15 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e } //01 00 
		$a_01_5 = {e8 11 00 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e } //01 00 
		$a_01_6 = {e8 47 00 00 00 68 74 74 70 3a 2f 2f 68 6f 73 74 74 68 65 6e 70 6f 73 74 2e 6f 72 67 2f 75 70 6c 6f 61 64 73 2f } //01 00 
		$a_01_7 = {2f 72 65 70 6f 72 74 5f 4e 5f } //00 00  /report_N_
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gatak_DR__2{
	meta:
		description = "Trojan:Win32/Gatak.DR!!Gatak.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 62 5f c6 45 63 73 c6 45 64 74 c6 45 65 61 c6 45 66 72 c6 45 67 74 c6 45 68 5f c6 45 69 25 c6 45 6a 64 c6 45 6b 5f c6 45 6c 25 c6 45 6d 64 } //01 00 
		$a_01_1 = {c6 45 66 5f c6 45 67 65 c6 45 68 72 c6 45 69 72 c6 45 6a 32 c6 45 6b 5f c6 45 6c 5f c6 45 6d 25 c6 45 6e 64 } //01 00 
		$a_01_2 = {c6 45 5e 5f c6 45 5f 66 c6 45 60 69 c6 45 61 6e c6 45 62 69 c6 45 63 73 c6 45 64 68 c6 45 65 5f c6 45 66 25 c6 45 67 64 c6 45 68 5f c6 45 69 25 c6 45 6a 64 c6 45 6b 5f c6 45 6c 5f c6 45 6d 25 c6 45 6e 64 } //01 00 
		$a_03_3 = {8b 75 10 80 3e 89 59 59 0f 85 90 01 04 80 7e 01 50 0f 85 90 01 04 80 7e 02 4e 0f 85 90 01 04 80 7e 03 47 0f 85 90 00 } //01 00 
		$a_01_4 = {38 5d f9 74 0a c6 45 fc 36 c6 45 fd 34 eb 08 c6 45 fc 33 c6 45 fd 32 } //01 00 
		$a_01_5 = {72 e0 8b 46 04 c6 00 7e 8d 45 e8 50 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70 c6 45 ec 00 } //01 00 
		$a_01_6 = {c6 45 fc 7e c6 45 fd 58 c6 45 fe 58 88 5d ff ff 15 } //01 00 
		$a_01_7 = {8b c6 99 f7 7d 10 8b 45 0c 8a 04 02 02 04 0e 8a 14 0e 00 45 0b 0f b6 45 0b 03 c1 8a 18 88 1c 0e 46 3b f7 88 10 7c d9 } //00 00 
	condition:
		any of ($a_*)
 
}