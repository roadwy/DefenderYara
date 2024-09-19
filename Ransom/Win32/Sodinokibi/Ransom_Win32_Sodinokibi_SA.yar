
rule Ransom_Win32_Sodinokibi_SA{
	meta:
		description = "Ransom:Win32/Sodinokibi.SA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 49 53 } //SOFTIS  1
		$a_80_1 = {4d 4f 44 4c 49 53 } //MODLIS  1
		$a_80_2 = {6d 70 73 76 63 2e 64 6c 6c } //mpsvc.dll  1
		$a_80_3 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //MsMpEng.exe  1
		$a_02_4 = {ba 88 55 0c 00 a3 ?? ?? ?? ?? ?? ?? e8 [0-20] ba d0 56 00 00 c7 ?? ?? ?? ?? ?? ?? e8 } //5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*5) >=7
 
}
rule Ransom_Win32_Sodinokibi_SA_2{
	meta:
		description = "Ransom:Win32/Sodinokibi.SA,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {03 c0 01 47 30 11 4f 34 01 57 30 8b 57 78 8b c2 11 77 34 8b 77 7c 8b ce 0f a4 c1 04 c1 e0 04 01 47 28 8b c2 11 4f 2c 8b ce 0f a4 c1 01 03 c0 01 47 28 11 4f 2c 01 57 28 8b 57 70 8b c2 11 77 2c 8b 77 74 8b ce 0f a4 c1 04 c1 e0 04 01 47 20 8b c2 11 4f 24 8b ce 0f a4 c1 01 03 c0 01 47 20 11 4f 24 01 57 20 8b 57 68 8b c2 11 77 24 8b 77 6c 8b ce 0f a4 c1 04 c1 e0 04 01 47 18 8b c2 11 4f 1c 8b ce 0f a4 c1 01 03 c0 01 47 18 11 4f 1c 01 57 18 8b 57 60 8b c2 11 77 1c 8b 77 64 } //1
		$a_01_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 16-byte k
		$a_01_2 = {f7 6f 38 03 c8 8b 43 48 13 f2 f7 6f 20 03 c8 8b 43 38 13 f2 f7 6f 30 03 c8 8b 43 40 13 f2 f7 6f 28 03 c8 8b 43 28 13 f2 f7 6f 40 03 c8 8b 45 08 13 f2 89 48 68 89 70 6c 8b 43 38 f7 6f 38 8b c8 8b f2 8b 43 28 f7 6f 48 03 c8 13 f2 8b 43 48 f7 6f 28 03 c8 8b 43 30 13 f2 f7 6f 40 0f a4 ce 01 03 c9 03 c8 8b 43 40 13 f2 f7 6f 30 03 c8 8b 45 08 13 f2 89 48 70 89 70 74 8b 43 38 f7 6f 40 8b c8 } //1
		$a_01_3 = {33 c0 8b 5a 68 8b 52 6c 0f a4 fe 08 c1 e9 18 0b c6 c1 e7 08 8b 75 08 0b cf 89 4e 68 8b ca 89 46 6c 33 c0 8b 7e 60 8b 76 64 0f a4 da 19 c1 e9 07 0b c2 c1 e3 19 8b 55 08 0b cb 89 4a 60 8b cf 89 42 64 33 c0 8b 5a 10 8b 52 14 0f ac f7 15 c1 e1 0b c1 ee 15 0b c7 0b ce 8b 75 } //1
		$a_01_4 = {c1 01 c1 ee 1f 0b d1 03 c0 0b f0 8b c2 33 43 24 8b ce 33 4b 20 33 4d e4 33 45 e0 89 4b 20 8b cb 8b 5d e0 89 41 24 8b ce 33 4d e4 8b c2 31 4f 48 33 c3 8b cf 31 41 4c 8b c7 8b ce 33 48 70 8b c2 33 47 74 33 4d e4 33 c3 89 4f 70 8b cf 89 41 74 8b } //1
		$a_01_5 = {8b 43 40 f7 6f 08 03 c8 8b 03 13 f2 f7 6f 48 03 c8 8b 43 48 13 f2 f7 2f 03 c8 8b 43 08 13 f2 f7 6f 40 03 c8 8b 43 30 13 f2 f7 6f 18 03 c8 8b 43 18 13 f2 f7 6f 30 03 c8 8b 43 38 13 f2 f7 6f 10 03 c8 8b 43 10 13 f2 f7 6f 38 03 c8 8b 43 28 13 f2 } //1
		$a_01_6 = {8b ce 33 4d f8 8b c2 33 c3 31 4f 18 8b cf 31 41 1c 8b c7 8b ce 33 48 40 8b c2 33 4d f8 33 47 44 89 4f 40 33 c3 8b cf 89 41 44 8b c7 8b ce 33 48 68 8b c2 33 47 6c 33 4d f8 33 c3 89 4f 68 8b cf 89 41 6c 8b ce 8b } //1
		$a_01_7 = {36 7d 49 30 85 35 c2 c3 68 60 4b 4b 7a be 83 53 ab e6 8e 42 f9 c6 62 a5 d0 6a ad c6 f1 7d f6 1d 79 cd 20 fc e7 3e e1 b8 1a 43 38 12 c1 56 28 1a 04 c9 22 55 e0 d7 08 bb 9f 0b 1f 1c b9 13 06 35 } //1
		$a_01_8 = {c2 c1 ee 03 8b 55 08 0b ce 89 4a 4c 8b cf 89 42 48 33 c0 8b 72 30 8b 52 34 c1 e9 0c 0f a4 df 14 0b c7 c1 e3 14 8b 7d 08 0b cb 89 4f 30 8b ce 89 47 34 33 c0 c1 e1 0c 0f ac d6 14 0b c6 c1 ea 14 89 47 08 0b ca } //1
		$a_01_9 = {8b f2 8b 43 38 f7 6f 28 03 c8 8b 43 18 13 f2 f7 6f 48 03 c8 8b 43 28 13 f2 f7 6f 38 03 c8 8b 43 40 13 f2 f7 6f 20 0f a4 ce 01 03 c9 03 c8 8b 43 20 13 f2 f7 6f 40 03 c8 8b 43 30 13 f2 f7 6f 30 03 c8 } //1
		$a_01_10 = {33 45 fc 31 4b 28 8b cb 31 41 2c 8b ce 8b c3 33 48 50 8b c2 33 43 54 33 cf 33 45 fc 89 4b 50 8b cb 89 41 54 8b ce 8b c3 33 48 78 8b c2 33 43 7c 33 cf 33 45 fc 89 4b 78 8b cb 89 41 7c 33 b1 a0 } //1
		$a_01_11 = {52 24 0f a4 fe 0e c1 e9 12 0b c6 c1 e7 0e 8b 75 08 0b cf 89 4e 20 8b ca 89 46 24 33 c0 8b 7e 78 8b 76 7c 0f a4 da 1b c1 e9 05 0b c2 c1 e3 1b 8b 55 08 0b cb 89 4a 78 8b cf 89 42 7c 33 c0 8b 9a } //1
		$a_01_12 = {f2 8b 43 38 f7 6f 20 03 c8 8b 43 40 13 f2 f7 6f 18 03 c8 8b 43 10 13 f2 f7 6f 48 03 c8 8b 43 28 13 f2 f7 6f 30 03 c8 8b 43 20 13 f2 f7 6f 38 03 c8 8b 43 30 13 f2 f7 6f 28 03 c8 8b 43 48 13 f2 } //1
		$a_01_13 = {8b 47 30 13 f2 f7 6f 40 03 c8 13 f2 0f a4 ce 01 89 73 74 03 c9 89 4b 70 8b 47 30 f7 6f 48 8b c8 8b f2 8b 47 38 f7 6f 40 03 c8 13 f2 0f a4 ce 01 89 73 7c 03 c9 89 4b 78 8b 47 38 f7 6f 48 8b c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}