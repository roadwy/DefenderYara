
rule Trojan_Win32_EmotetCrypt_DO_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 da 2b d9 03 5c 24 14 0f b6 14 3b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 ca 8d 04 71 8a 0c 38 8b 44 24 20 30 08 } //5
		$a_81_1 = {25 71 51 6e 31 2b 25 32 44 74 61 68 48 38 4b 50 25 5f 4a 45 73 4e 54 49 65 46 75 57 70 34 36 4f 3c 73 71 35 6a 32 69 56 4e 30 74 6c 28 6d 53 62 71 67 62 35 7a 68 32 29 59 51 24 44 35 73 5e 38 6a } //1 %qQn1+%2DtahH8KP%_JEsNTIeFuWp46O<sq5j2iVN0tl(mSbqgb5zh2)YQ$D5s^8j
		$a_01_2 = {8b 4c 24 1c 8b 44 24 10 8a 14 01 8a 4c 3c 20 32 d1 88 10 40 89 44 24 10 8b 44 24 14 48 89 44 24 14 0f 85 } //5
		$a_81_3 = {44 6c 36 49 58 58 50 35 66 69 23 79 4e 79 34 47 46 73 2a 59 50 39 65 4d 78 59 52 4f 24 69 58 34 7c 5a 47 7c 44 24 54 73 39 66 7d 61 62 40 42 67 59 73 57 79 65 32 23 54 73 4c 50 23 71 34 65 77 30 2a 76 42 25 6c 7d 4d 2a 38 37 57 59 } //1 Dl6IXXP5fi#yNy4GFs*YP9eMxYRO$iX4|ZG|D$Ts9f}ab@BgYsWye2#TsLP#q4ew0*vB%l}M*87WY
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_01_2  & 1)*5+(#a_81_3  & 1)*1) >=6
 
}