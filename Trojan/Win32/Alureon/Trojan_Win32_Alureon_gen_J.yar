
rule Trojan_Win32_Alureon_gen_J{
	meta:
		description = "Trojan:Win32/Alureon.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 11 00 00 "
		
	strings :
		$a_03_0 = {24 04 76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1 } //2
		$a_03_1 = {39 4c 24 08 76 14 8b 44 24 04 8a d1 03 c1 80 c2 ?? 30 10 41 3b 4c 24 08 72 ec } //2
		$a_03_2 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed } //2
		$a_03_3 = {83 2c 24 0a c6 (44 24|45) ?? b8 89 (44 24|45) ?? 66 c7 (44 24|45) ?? ff e0 } //2
		$a_03_4 = {39 28 75 d2 eb 07 8b 1c b5 ?? ?? ?? ?? 83 c7 04 81 ff ?? ?? ?? ?? 7c ab 5f } //1
		$a_03_5 = {eb 06 8d 58 01 6a 5c 53 ff d7 85 c0 59 59 75 f2 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 85 c0 59 59 74 07 } //2
		$a_01_6 = {5c 00 6b 00 6e 00 6f 00 77 00 6e 00 64 00 6c 00 6c 00 73 00 5c 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00 } //2
		$a_80_7 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 61 64 76 61 70 69 33 32 2e 64 6c 6c } //\\?\globalroot\systemroot\system32\advapi32.dll  1
		$a_00_8 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 74 64 6c } //1 \\?\globalroot\tdl
		$a_01_9 = {75 3d 25 73 26 69 3d 25 73 26 70 3d 25 73 26 66 3d 25 73 26 63 3d 25 64 26 64 3d 25 64 } //1 u=%s&i=%s&p=%s&f=%s&c=%d&d=%d
		$a_01_10 = {72 3d 25 73 26 66 3d 25 73 26 70 3d 25 73 26 75 3d 25 73 26 69 3d 25 73 26 67 3d 25 64 } //1 r=%s&f=%s&p=%s&u=%s&i=%s&g=%d
		$a_01_11 = {2f 64 6c 69 6e 6b 2f 68 77 69 7a 2e 68 74 6d 6c } //1 /dlink/hwiz.html
		$a_01_12 = {50 6a 40 6a 15 03 cf 51 ff d5 8b 4b 28 8b 14 31 8d 04 31 } //2
		$a_03_13 = {50 8b 43 28 6a 40 6a 15 03 c7 50 ff 15 ?? ?? ?? ?? 8b 43 28 6a 05 } //2
		$a_03_14 = {8b 46 28 03 45 0c 6a 40 6a 15 50 89 75 f0 ff 15 ?? ?? ?? ?? 8b 46 28 8b 4d 0c 8d 34 38 8d 3c 08 6a 05 } //2
		$a_03_15 = {3b c6 89 45 08 74 47 6a 40 68 00 30 00 00 40 50 56 ff 15 ?? ?? ?? ?? 8b f8 3b fe 74 31 } //2
		$a_01_16 = {5f 89 48 58 8b c6 5e 5b c9 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*1+(#a_03_5  & 1)*2+(#a_01_6  & 1)*2+(#a_80_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*2+(#a_03_13  & 1)*2+(#a_03_14  & 1)*2+(#a_03_15  & 1)*2+(#a_01_16  & 1)*1) >=3
 
}