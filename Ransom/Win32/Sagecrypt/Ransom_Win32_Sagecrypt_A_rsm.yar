
rule Ransom_Win32_Sagecrypt_A_rsm{
	meta:
		description = "Ransom:Win32/Sagecrypt.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 13 00 00 "
		
	strings :
		$a_01_0 = {32 51 ff 83 c3 01 88 53 ff } //2
		$a_03_1 = {52 74 20 a1 ?? ?? ?? ?? 8b 98 ?? ?? 00 00 ff 90 90 ?? 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 ff d3 } //2
		$a_01_2 = {c7 02 65 78 70 61 c7 42 04 6e 64 20 33 c7 42 08 32 2d 62 79 c7 42 0c 74 65 20 6b } //1
		$a_01_3 = {66 c7 40 1c 00 00 c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 c7 40 10 f0 e1 d2 c3 } //1
		$a_01_4 = {80 3c 33 2b 75 04 c6 04 33 2d 80 3c 33 2f 75 04 c6 04 33 5f } //1
		$a_03_5 = {43 00 3a 00 8b 7d 08 c7 45 ?? 5c 00 00 00 eb 11 } //2
		$a_03_6 = {66 83 3b 57 0f 85 ?? 00 00 00 66 83 7b 02 53 75 7b 66 83 7b 04 2d } //2
		$a_03_7 = {0f 45 d9 8b 92 ?? ?? 00 00 89 5c 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 50 41 f3 5c 89 3c 24 ff d2 } //3
		$a_00_8 = {5b 63 6f 6e 66 69 67 2d 2d 2d 2d 2d 2d 2d 2d 2d } //2 [config---------
		$a_00_9 = {00 25 73 5c 25 73 2e 65 78 65 00 } //1
		$a_00_10 = {00 25 73 5c 25 73 2e 74 6d 70 00 } //1
		$a_00_11 = {00 25 73 5c 66 25 75 2e 68 74 61 00 } //2
		$a_00_12 = {00 25 73 5c 66 25 75 2e 76 62 73 00 } //2
		$a_00_13 = {00 25 53 2e 2e 2e 00 } //1
		$a_00_14 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73 } //1 桺愀r湥搀e獥
		$a_00_15 = {68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f } //1 楨瘀i牴洀s潮
		$a_00_16 = {00 61 63 79 22 20 3a 20 00 } //1
		$a_00_17 = {00 6c 61 74 22 20 3a 20 00 } //1
		$a_00_18 = {00 6c 6e 67 22 20 3a 20 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2+(#a_03_7  & 1)*3+(#a_00_8  & 1)*2+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1) >=10
 
}
rule Ransom_Win32_Sagecrypt_A_rsm_2{
	meta:
		description = "Ransom:Win32/Sagecrypt.A!rsm,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 63 79 22 20 3a 20 00 6c 61 74 22 20 3a 20 00 6c 6e 67 22 20 3a 20 } //10
		$a_01_1 = {25 73 5c 66 25 75 2e 76 62 73 } //10 %s\f%u.vbs
		$a_01_2 = {73 74 00 5c 5c 3f 5c 25 53 00 25 73 5c 66 25 75 2e 68 74 61 } //10 瑳尀㽜╜S猥晜甥栮慴
		$a_01_3 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73 00 66 61 00 66 72 00 69 74 00 6b 72 00 6e 6c 00 70 74 00 68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}