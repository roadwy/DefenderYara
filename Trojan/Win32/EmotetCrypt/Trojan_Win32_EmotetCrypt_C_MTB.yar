
rule Trojan_Win32_EmotetCrypt_C_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0d 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 33 03 45 fc f7 f1 8a 45 17 02 04 33 89 55 fc 8b 5d fc 8a 14 32 02 55 17 88 04 33 8b 5d 10 8b 45 fc 88 14 33 0f b6 04 30 0f b6 d2 03 c2 33 d2 f7 f1 03 55 1c 8a 04 32 8b 55 08 02 45 17 32 04 3a 88 07 47 ff 4d 18 75 } //1
		$a_03_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5c 24 18 ff 15 ?? ?? ?? ?? 8a 0c 33 8b 44 24 14 02 4c 24 28 8b 54 24 1c 32 0c 02 83 c0 01 83 6c 24 10 01 88 48 ff 89 44 24 14 75 } //1
		$a_01_2 = {8b c3 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 8b f8 8b 44 24 1c 8d 34 01 33 d2 8b c1 f7 f7 8a 04 2e 8a 14 1a 32 d0 8b 44 24 20 41 3b c8 88 16 75 d0 5f 5e 5d 5b c3 } //1
		$a_03_3 = {0f b6 04 0f 0f b6 0c 0e 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 12 ff 15 ?? ?? ?? ?? 0f b6 54 24 12 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 18 30 0c 28 45 3b 6c 24 1c 7c ?? 8b 44 24 20 8a 54 24 13 5f 5e 88 18 5b 88 50 01 5d 59 c3 } //1
		$a_03_4 = {83 c8 04 6a 00 50 e8 ?? ?? ?? ?? 0f b6 54 24 11 a1 ?? ?? ?? ?? 8a 14 02 8b 44 24 14 8b 4c 24 1c 30 14 08 40 3b 44 24 20 89 44 24 14 0f 8c ?? ff ff ff 8a 4c 24 12 8b 44 24 24 8a 54 24 13 5f 5e 5d 5b } //1
		$a_03_5 = {83 c4 08 8b c8 e8 ?? ?? ?? ?? 0f b6 55 f7 a1 ?? ?? ?? ?? 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 e9 ?? ?? ff ff 8b 55 10 8a 45 fe 88 02 8b 4d 10 8a 55 ff 88 51 01 8b e5 5d c3 } //1
		$a_03_6 = {0f b6 55 f7 a1 ?? ?? ?? ?? 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 e9 ?? ?? ff ff 8b 55 10 8a 45 fe 88 02 8b 4d 10 8a 55 ff 88 51 01 8b e5 5d c3 } //1
		$a_03_7 = {ff d6 0f b6 55 ff 8b 45 08 8b 7d f8 8b 0d ?? ?? ?? ?? 03 c7 8a 14 0a 30 10 47 3b 7d 0c 89 7d f8 7c ?? 8a 4d fe 8b 45 10 8a 55 fd 5f 5e 5b 88 08 88 50 01 c9 c3 } //1
		$a_03_8 = {0f b6 4c 24 11 8b 15 ?? ?? ?? ?? 8a 14 11 8b 44 24 18 8b 4c 24 20 30 14 08 8b 4c 24 24 40 3b c1 89 44 24 18 0f 8c ?? ?? ff ff 8b 44 24 28 8a 4c 24 12 8a 54 24 13 5f 5d 5b 88 08 88 50 01 5e 83 c4 0c c3 } //1
		$a_03_9 = {8a 0c 1a 88 04 1a 8b 45 fc 02 cd 88 0c 18 0f b6 04 1a 0f b6 c9 03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 4d 08 03 55 f4 0f b6 04 1a 02 45 0f 32 44 31 ff 8a 6d 0f 88 46 ff 4f 75 ?? 5f 5e 5b 8b e5 5d c3 } //1
		$a_03_10 = {0f b6 54 24 12 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 18 30 0c 28 8b 44 24 1c 45 3b e8 0f 8c ?? ff ff ff 8b 44 24 20 8a 54 24 13 5f 88 18 5b 5e 88 50 01 5d 59 c3 } //1
		$a_01_11 = {53 58 8d 70 01 8d 49 00 8a 10 83 c0 01 84 d2 75 f7 2b c6 50 5f 8b 44 24 1c 8d 34 01 33 d2 8b c1 f7 f7 83 c1 01 8a 14 1a 32 14 2e 3b 4c 24 20 88 16 75 cd 5f 5e 5d 5b c3 } //1
		$a_01_12 = {f7 ff 8a 04 0e 0f b6 fa 88 54 24 13 8a 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 8a 14 08 8b 44 24 18 30 14 28 8b 44 24 1c 45 3b e8 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=1
 
}