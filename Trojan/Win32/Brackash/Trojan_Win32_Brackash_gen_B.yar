
rule Trojan_Win32_Brackash_gen_B{
	meta:
		description = "Trojan:Win32/Brackash.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e8 06 00 00 00 8b 75 08 c6 45 e2 68 c6 45 e7 c3 c6 45 ff 00 33 c0 } //01 00 
		$a_03_1 = {74 35 8b 01 33 d2 52 50 a1 90 01 04 99 3b 54 24 04 75 03 3b 04 24 5a 58 75 07 b8 05 00 00 00 eb 28 51 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ff 15 90 01 04 eb 13 51 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ff 15 90 01 04 5d c2 90 00 } //01 00 
		$a_03_2 = {74 49 8b 45 f4 50 8d 45 f0 50 e8 90 01 02 ff ff 8b 45 f0 50 8d 45 e4 e8 90 01 02 ff ff 8b 45 e4 8d 55 e8 e8 90 01 02 ff ff 8d 45 e8 ba 90 01 04 e8 90 01 02 ff ff 8b 45 e8 50 8d 45 ec 50 e8 90 01 02 ff ff 8b 55 ec 58 e8 90 01 02 ff ff 75 16 90 00 } //01 00 
		$a_03_3 = {89 45 fc 83 fb 05 90 03 06 02 0f 85 a2 00 00 00 75 51 83 7d fc 00 90 03 06 02 0f 85 98 00 00 00 75 4b 33 f6 8d 1c 37 8d 55 f4 8b 43 3c e8 90 01 02 ff ff 8b 43 44 33 d2 52 50 a1 90 01 04 99 3b 54 24 04 75 03 3b 04 24 5a 58 90 00 } //01 00 
		$a_01_4 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 6c 69 6b 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}