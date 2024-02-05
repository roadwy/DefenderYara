
rule Trojan_Win32_FormBook_SISN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.SISN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 12 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 55 f8 88 55 ff 0f b6 45 ff c1 f8 05 0f b6 4d ff c1 e1 03 0b c1 88 45 ff 0f b6 55 ff 03 55 f8 88 55 ff 0f b6 45 ff } //01 00 
		$a_01_1 = {0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 da 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff 81 } //01 00 
		$a_01_2 = {81 e9 92 00 00 00 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 83 e9 5e 88 4d ff 0f b6 55 ff f7 da 88 55 ff } //01 00 
		$a_01_3 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 83 e9 5e } //01 00 
		$a_01_4 = {0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 d2 88 55 ff 0f b6 45 ff f7 d8 } //01 00 
		$a_01_5 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff } //01 00 
		$a_01_6 = {88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 da 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff f7 d9 } //01 00 
		$a_01_7 = {0b ca 88 4d ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff f7 da } //01 00 
		$a_01_8 = {88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff d1 f8 } //01 00 
		$a_01_9 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff c1 f8 06 0f b6 4d ff c1 e1 02 } //01 00 
		$a_01_10 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff c1 f8 02 0f b6 4d ff c1 e1 06 0b c1 88 45 ff } //01 00 
		$a_01_11 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff } //01 00 
		$a_01_12 = {68 50 00 10 85 c0 59 a3 14 44 00 10 75 04 33 c0 eb 66 83 20 00 a1 14 44 00 10 68 04 60 00 10 68 00 60 00 10 a3 10 44 00 10 e8 ad 2e 00 00 ff 05 08 44 00 10 59 59 eb 3d 85 c0 75 39 a1 14 44 00 10 85 c0 74 30 8b 0d 10 44 00 10 56 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 14 44 00 10 83 ee 04 eb ea 50 ff 15 70 50 00 10 83 25 14 44 00 10 00 59 5e 6a 01 58 c2 0c 00 55 8b ec 53 8b 5d 08 56 8b 75 0c 57 8b 7d 10 85 f6 75 09 83 3d 08 44 00 10 00 eb 26 83 fe 01 74 05 83 fe 02 75 22 a1 18 44 00 10 85 c0 74 09 57 56 53 ff d0 85 } //01 00 
		$a_01_13 = {33 c0 eb 66 83 20 00 a1 bc 74 00 10 68 a8 74 00 10 68 a4 74 00 10 a3 c0 74 00 10 e8 7a 01 00 00 ff 05 b4 74 00 10 59 59 eb 3d 85 c0 75 39 a1 bc 74 00 10 85 c0 74 30 8b 0d c0 74 00 10 56 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 bc 74 00 10 83 ee 04 eb ea 50 ff 15 20 5a 00 10 83 25 bc 74 00 10 00 59 5e 6a 01 58 c2 0c 00 55 } //01 00 
		$a_01_14 = {33 58 00 00 77 64 6c 69 6c 63 6c 76 2e 64 6c 6c 00 00 00 00 00 70 2c 00 00 35 58 00 00 01 00 63 63 } //01 00 
		$a_01_15 = {32 0d 42 17 c2 ec 67 66 46 78 01 06 4a bd 81 df d9 b7 41 b9 78 95 35 f6 13 3d 1f f7 7d e6 e7 01 8d e3 1e } //01 00 
		$a_01_16 = {33 45 f8 88 45 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff } //01 00 
		$a_01_17 = {4d 0c 6b c9 30 01 c8 8b 4d f4 8b 49 60 0f b7 55 0c 83 c2 01 6b d2 30 01 d1 8b 55 f4 8b 52 5c 0f } //00 00 
	condition:
		any of ($a_*)
 
}