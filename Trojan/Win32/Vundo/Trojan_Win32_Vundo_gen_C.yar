
rule Trojan_Win32_Vundo_gen_C{
	meta:
		description = "Trojan:Win32/Vundo.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 85 c0 74 27 8a 08 80 f9 ff 75 0d 80 78 01 25 75 07 8b 40 02 8b 00 eb 13 80 f9 e9 75 0e 83 7c 24 08 00 74 07 8b 48 01 8d 44 08 05 } //01 00 
		$a_01_1 = {80 c2 61 83 65 08 00 88 11 33 d2 6a 05 5b 8b c7 f7 f3 8d 71 01 0f be 09 6a 19 0f be c2 03 c1 99 59 f7 f9 6a 0a 8b ce 8b c7 80 c2 61 88 16 33 d2 5e f7 f6 ff 45 08 39 5d 08 8b f8 7c cc } //01 00 
		$a_01_2 = {80 c2 61 29 75 08 88 16 8b c1 83 e0 01 6a 05 40 33 d2 5b 83 f8 01 8d 7e 01 6a 19 8b c1 75 13 f7 f3 } //01 00 
		$a_03_3 = {6a 02 57 8b f0 6a f3 56 ff 15 90 01 04 57 8d 44 24 90 01 01 50 6a 0d 68 90 00 } //01 00 
		$a_01_4 = {eb 2f 6a 02 56 6a f3 53 c7 45 f8 0d 00 00 00 ff d7 56 8d 45 f8 50 ff 75 f8 8d 45 dc 50 53 } //02 00 
		$a_02_5 = {89 45 14 74 53 33 ff f7 06 fc ff ff ff 76 49 68 04 01 00 00 8d 85 fc fe ff ff 50 ff 34 bb ff 75 08 ff 15 90 01 04 85 c0 74 23 8d 85 fc fe ff ff 50 ff 15 90 01 04 68 90 01 04 8d 85 fc fe ff ff 50 ff 15 90 01 04 85 c0 75 14 8b 06 90 00 } //02 00 
		$a_03_6 = {6a 0d ff 75 fc 68 90 01 04 ff 15 90 01 04 85 c0 75 15 ff b5 90 01 02 ff ff 53 6a 01 ff 15 90 01 04 8b f8 3b fb 75 15 8d 85 90 01 02 ff ff 50 ff 75 f8 e8 90 01 04 85 c0 75 9a eb 0b 53 90 00 } //01 00 
		$a_03_7 = {2f 3f 63 6d 70 3d 76 6d 74 65 6b 5f 90 02 0a 26 6c 69 64 3d 72 75 6e 26 75 69 64 3d 25 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}