
rule Ransom_Win32_Shieldcrypt_A{
	meta:
		description = "Ransom:Win32/Shieldcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {83 f8 09 74 14 83 f8 07 74 0f 83 f8 08 74 0a 83 f8 06 74 05 83 f8 04 75 1a e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 3d 00 30 00 00 } //2
		$a_01_1 = {00 26 6e 75 6d 62 65 72 73 3d 00 } //1
		$a_01_2 = {00 26 63 6f 75 6e 74 73 3d 00 } //1 ☀潣湵獴=
		$a_01_3 = {2f 74 65 73 74 5f 73 69 74 65 5f 73 63 72 69 70 74 73 2f 6d 6f 64 75 6c 73 2f 74 72 61 66 66 69 63 2f 67 65 74 5f 69 6e 66 6f 2e 70 68 70 } //1 /test_site_scripts/moduls/traffic/get_info.php
		$a_01_4 = {2f 00 43 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 /C vssadmin.exe Delete Shadows /All /Quiet
		$a_01_5 = {2f 00 43 00 20 00 62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 4e 00 6f 00 } //1 /C bcdedit /set {default} recoveryenabled No
		$a_01_6 = {2f 00 43 00 20 00 62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 62 00 6f 00 6f 00 74 00 73 00 74 00 61 00 74 00 75 00 73 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 69 00 67 00 6e 00 6f 00 72 00 65 00 61 00 6c 00 6c 00 66 00 61 00 69 00 6c 00 75 00 72 00 65 00 73 00 } //1 /C bcdedit /set {default} bootstatuspolicy ignoreallfailures
		$a_01_7 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 76 00 73 00 73 00 } //1 net stop vss
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Ransom_Win32_Shieldcrypt_A_2{
	meta:
		description = "Ransom:Win32/Shieldcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 19 00 00 "
		
	strings :
		$a_01_0 = {6a 01 ff 75 f8 68 10 66 00 00 ff 75 f4 } //1
		$a_01_1 = {50 68 11 00 00 08 6a 01 } //1
		$a_03_2 = {8a 16 0f b6 c3 fe c3 0f b6 80 ?? ?? ?? ?? 02 c2 02 f0 0f b6 ce 8d 76 01 0f b6 04 39 88 46 ff 0f b6 c3 88 14 39 33 c9 80 fb ?? 0f 44 c1 ff 4d 08 8a d8 75 cc } //2
		$a_03_3 = {8b f0 83 fe 03 74 ?? 83 fe 02 74 ?? 83 fe 04 74 ?? 83 fe 06 0f 85 ?? 00 00 00 ff 74 24 10 } //1
		$a_01_4 = {c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75 ed } //1
		$a_01_5 = {75 13 b8 d7 f0 3a ea } //1
		$a_03_6 = {ff d7 8b 45 f0 85 c0 75 06 43 83 fb 1a 7c ?? 8b 4d fc 5f 5e 33 cd 5b e8 } //2
		$a_80_7 = {00 41 46 45 45 31 36 42 43 00 } //  1
		$a_80_8 = {28 50 45 52 53 4f 4e 41 4c 20 49 44 45 4e 54 49 46 49 43 41 54 49 4f 4e 29 3a 20 25 30 38 58 25 30 38 58 } //(PERSONAL IDENTIFICATION): %08X%08X  1
		$a_80_9 = {43 72 79 70 74 6f 53 68 69 65 6c 64 } //CryptoShield  1
		$a_80_10 = {72 65 73 74 6f 72 69 6e 67 5f 73 75 70 40 } //restoring_sup@  1
		$a_80_11 = {72 65 73 74 6f 72 69 6e 67 5f 72 65 73 65 72 76 65 40 } //restoring_reserve@  1
		$a_80_12 = {34 35 2e 37 36 2e 38 31 2e 31 31 30 } //45.76.81.110  1
		$a_80_13 = {6d 61 69 6c 73 75 70 6c 6f 61 64 2e 70 68 70 } //mailsupload.php  1
		$a_80_14 = {2f 74 65 73 74 5f 73 69 74 65 5f 73 63 72 69 70 74 73 2f 6d 6f 64 75 6c 73 2f 63 6f 6e 6e 65 63 74 73 2f } ///test_site_scripts/moduls/connects/  1
		$a_80_15 = {25 73 5c 4f 66 66 69 63 65 54 61 62 5c 46 61 76 6f 72 69 74 65 73 } //%s\OfficeTab\Favorites  1
		$a_80_16 = {5c 45 78 63 65 6c 46 61 76 6f 72 69 74 65 2e 61 63 6c } //\ExcelFavorite.acl  1
		$a_80_17 = {25 73 5c 4d 69 63 72 6f 53 6f 66 74 57 61 72 65 } //%s\MicroSoftWare  1
		$a_80_18 = {25 73 5c 31 46 41 41 58 42 32 2e 74 6d 70 } //%s\1FAAXB2.tmp  1
		$a_80_19 = {25 73 5c 25 73 2e 48 54 4d 4c } //%s\%s.HTML  1
		$a_80_20 = {25 73 5c 25 73 2e 54 58 54 } //%s\%s.TXT  1
		$a_80_21 = {25 73 5c 53 74 6f 70 20 52 61 6e 73 6f 6d 77 61 72 65 20 44 65 63 72 79 70 74 73 20 54 6f 6f 6c 73 2e 65 78 65 } //%s\Stop Ransomware Decrypts Tools.exe  1
		$a_80_22 = {25 73 5c 4d 69 63 72 6f 53 6f 66 74 57 61 72 65 5c 53 6d 61 72 74 53 63 72 65 65 6e 5c 25 73 2e 65 78 65 } //%s\MicroSoftWare\SmartScreen\%s.exe  1
		$a_80_23 = {6d 6f 6d 6f 72 79 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 72 65 61 64 2e } //momory could not be read.  1
		$a_80_24 = {57 69 6e 64 6f 77 73 20 53 6d 61 72 74 53 63 72 65 65 6e 20 55 70 64 61 74 65 72 } //Windows SmartScreen Updater  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*2+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1+(#a_80_22  & 1)*1+(#a_80_23  & 1)*1+(#a_80_24  & 1)*1) >=8
 
}