
rule Trojan_Win32_Trickbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 83 ?? 20 33 d0 8b 4d ?? 88 11 8b 55 ?? 03 55 ?? 89 55 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d1 03 f1 89 54 24 ?? 8a 00 89 74 24 ?? 88 44 24 ?? 8b 44 24 ?? 33 ff 33 ed 66 8b 3e 8b 74 24 ?? 8d 3c be 8b 32 8a 54 24 ?? 03 f9 03 f1 84 d2 74 ?? 8b 54 24 ?? 8b de 2b da 8a 14 03 84 d2 74 } //1
		$a_01_1 = {38 45 31 35 41 73 74 32 52 29 74 31 5a 42 4d } //1 8E15Ast2R)t1ZBM
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 03 c7 f7 f1 8b 45 ?? 8a 0c 10 88 0e 88 1c 10 8b 0d ?? ?? ?? ?? 03 c2 ff 45 ?? 46 39 4d ?? 89 55 ?? 72 } //5
		$a_81_1 = {65 4a 5a 5e 6e 52 4d 26 59 78 6d 6a 55 3c 62 69 5e 3f 73 26 74 70 6b 37 77 63 57 21 52 33 5f 59 4d 6e 51 7a 42 26 5e 31 43 43 57 53 4f 3c 71 3f 63 31 52 62 4d 5a 61 65 55 75 25 46 35 45 6d 2a 72 55 26 55 54 5f 72 } //1 eJZ^nRM&YxmjU<bi^?s&tpk7wcW!R3_YMnQzB&^1CCWSO<q?c1RbMZaeUu%F5Em*rU&UT_r
		$a_81_2 = {46 57 53 65 38 26 4f 4f 31 6f 42 33 6f 43 58 46 40 2b 36 55 69 77 26 31 48 7a 4b 52 29 28 33 6e 37 66 71 50 51 63 46 71 55 5a 37 65 72 4f 36 } //1 FWSe8&OO1oB3oCXF@+6Uiw&1HzKR)(3n7fqPQcFqUZ7erO6
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=6
 
}
rule Trojan_Win32_Trickbot_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 15 00 00 "
		
	strings :
		$a_01_0 = {74 37 4f 24 61 48 21 21 47 23 2a 5e 49 70 69 } //10 t7O$aH!!G#*^Ipi
		$a_01_1 = {54 31 43 5f 24 6c 65 71 31 42 6c 21 46 65 43 } //10 T1C_$leq1Bl!FeC
		$a_01_2 = {52 35 34 57 40 54 57 6a 57 21 72 23 6d 6a 33 } //10 R54W@TWjW!r#mj3
		$a_01_3 = {5a 35 55 77 4b 5e 25 28 41 64 21 66 63 2a 37 } //10 Z5UwK^%(Ad!fc*7
		$a_01_4 = {48 46 76 31 33 26 75 36 50 37 44 30 70 79 65 } //10 HFv13&u6P7D0pye
		$a_01_5 = {61 75 4a 76 75 55 24 5a 32 46 37 6f 32 6b 66 } //10 auJvuU$Z2F7o2kf
		$a_01_6 = {31 4c 52 3f 56 37 4d 58 32 4e 79 39 6e 21 23 } //10 1LR?V7MX2Ny9n!#
		$a_01_7 = {3f 67 29 7a 26 34 3f 7a 61 55 53 76 51 6f 29 } //10 ?g)z&4?zaUSvQo)
		$a_01_8 = {3f 68 44 24 71 62 6a 79 4f 4c 48 33 65 25 43 } //10 ?hD$qbjyOLH3e%C
		$a_01_9 = {7a 4c 46 71 34 38 52 40 31 5a 30 62 32 57 67 } //10 zLFq48R@1Z0b2Wg
		$a_01_10 = {66 34 50 45 52 28 49 44 67 23 6d 68 74 31 57 } //10 f4PER(IDg#mht1W
		$a_01_11 = {65 37 77 6d 73 4d 55 37 79 6e 64 6a 31 66 28 } //10 e7wmsMU7yndj1f(
		$a_01_12 = {43 21 79 34 33 32 79 71 37 47 31 43 39 70 77 } //10 C!y432yq7G1C9pw
		$a_01_13 = {25 42 6c 40 3c 54 5a 67 6b 21 5a 57 6b 29 42 } //10 %Bl@<TZgk!ZWk)B
		$a_01_14 = {46 7a 72 28 28 3c 30 77 2b 52 74 25 24 31 66 } //10 Fzr((<0w+Rt%$1f
		$a_01_15 = {32 53 44 25 5e 21 65 77 50 51 53 33 43 57 77 } //10 2SD%^!ewPQS3CWw
		$a_01_16 = {53 74 75 70 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 68 61 68 61 68 } //1 Stup windows defender hahah
		$a_01_17 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //1 CryptAcquireContextW
		$a_01_18 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_01_19 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_01_20 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //1 GetMonitorInfoA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10+(#a_01_14  & 1)*10+(#a_01_15  & 1)*10+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=14
 
}