
rule Trojan_Win32_EmotetCrypt_B_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 2e 8a 04 37 88 14 37 88 04 2e 0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 1c ff 15 90 01 04 8b 44 24 18 8a 0c 18 8b 54 24 14 32 0c 32 83 c3 01 83 6c 24 24 01 88 4b ff 75 90 00 } //01 00 
		$a_01_1 = {33 d2 f7 f6 8b fa 8a 14 29 8a 04 0f 02 c3 02 d3 88 14 0f 88 04 29 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 24 46 89 74 24 24 03 54 24 18 0f b6 04 0a 8b 54 24 10 02 c3 32 44 32 ff ff 4c 24 14 88 46 ff 75 } //01 00 
		$a_01_2 = {89 54 24 20 ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 31 40 88 50 ff 89 44 24 24 ff 4c 24 10 75 8c 5f 5e 5d 5b 83 c4 0c c3 } //01 00 
		$a_03_3 = {ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 8b 4c 24 2c 8b 44 24 28 8a 14 01 8b 4c 24 1c 32 14 31 40 89 44 24 28 88 50 ff 8b 44 24 24 48 89 44 24 24 0f 85 90 01 01 ff ff ff 5f 5e 5d 5b 83 c4 08 c3 90 00 } //01 00 
		$a_01_4 = {0f b6 04 3b 0f b6 ca 03 c1 33 d2 f7 f5 8b ea ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 8b 44 24 24 8b 54 24 18 8a 0c 02 32 0c 2f 40 83 6c 24 14 01 88 48 ff 89 44 24 24 75 } //01 00 
		$a_03_5 = {88 14 0f 88 04 0e 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 35 90 01 04 03 54 24 14 8a 04 0a 8b 54 24 18 02 c3 32 04 2a 45 88 45 ff 8b 44 24 10 48 89 6c 24 24 89 44 24 10 75 90 00 } //01 00 
		$a_03_6 = {33 d2 f7 f1 8a 0c 33 02 4d ff 8a 04 32 02 45 ff 88 0c 32 88 04 33 8b ca 0f b6 0c 31 0f b6 c0 03 c1 89 55 f8 33 d2 f7 35 90 01 04 8b 4d f4 03 55 f0 8a 04 32 02 45 ff 32 04 39 88 07 47 ff 4d 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}