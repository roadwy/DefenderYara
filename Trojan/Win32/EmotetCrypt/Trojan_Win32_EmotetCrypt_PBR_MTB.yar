
rule Trojan_Win32_EmotetCrypt_PBR_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 15 ?? ?? ?? ff 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 8d ?? ?? ?? ff 0f b6 84 15 ?? ?? ?? ff 32 44 1f ff ff 4d ?? 88 43 ff } //1
		$a_03_1 = {0f b6 54 3c ?? 0f b6 c0 03 c2 99 f7 fb 0f b6 44 14 ?? 32 44 29 ff 83 6c 24 ?? 01 88 41 ff } //1
		$a_01_2 = {8a 44 3c 18 81 e2 ff 00 00 00 03 c2 99 f7 fb 8a 1c 29 8a 44 14 18 32 c3 88 01 } //1
		$a_81_3 = {70 21 61 61 28 78 3c 4c 54 32 78 39 25 35 76 64 24 5a 39 57 44 79 24 39 4c 2a 71 55 6b 78 48 34 63 42 38 69 74 } //1 p!aa(x<LT2x9%5vd$Z9WDy$9L*qUkxH4cB8it
		$a_81_4 = {5a 4c 47 5f 28 64 36 35 37 49 41 75 49 53 72 4b 47 45 37 3c 57 30 79 36 75 50 25 40 40 24 62 6f 21 4b 46 56 54 63 41 31 71 57 4d 48 6a 4e 25 76 6f 69 31 74 41 77 34 77 35 5e 34 4d 3e 36 21 3f 67 55 5f 69 6a 4e 4a 4e 52 5f 78 42 24 40 59 76 2b 21 6d 71 67 47 35 6d 64 77 21 } //1 ZLG_(d657IAuISrKGE7<W0y6uP%@@$bo!KFVTcA1qWMHjN%voi1tAw4w5^4M>6!?gU_ijNJNR_xB$@Yv+!mqgG5mdw!
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=1
 
}