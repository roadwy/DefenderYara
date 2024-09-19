
rule Trojan_Win32_Neoreblamy_ASM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 14 00 00 "
		
	strings :
		$a_01_0 = {5a 4b 6c 64 53 4b 42 4a 49 47 52 67 54 4a 62 62 70 64 57 67 4a 71 6d 65 45 64 72 75 6f 61 } //1 ZKldSKBJIGRgTJbbpdWgJqmeEdruoa
		$a_01_1 = {72 73 6d 5a 61 47 53 68 4b 67 43 4a 44 44 69 52 69 77 56 70 78 78 4c 54 51 6f 52 47 } //1 rsmZaGShKgCJDDiRiwVpxxLTQoRG
		$a_01_2 = {52 54 71 46 70 54 4f 44 5a 4e 70 6c 4d 77 79 75 7a 44 59 41 77 48 64 5a 68 57 79 42 71 48 4c 74 46 42 } //1 RTqFpTODZNplMwyuzDYAwHdZhWyBqHLtFB
		$a_01_3 = {79 51 45 73 71 61 42 6b 76 4d 6d 46 77 52 64 5a 51 7a 47 44 56 63 46 41 73 61 4a 46 4a 53 6c 53 69 50 4f 49 44 54 77 55 75 } //1 yQEsqaBkvMmFwRdZQzGDVcFAsaJFJSlSiPOIDTwUu
		$a_01_4 = {4f 6e 61 58 75 71 53 6d 6b 70 6e 53 58 7a 47 64 59 54 58 69 78 78 4e 48 49 64 42 51 77 74 } //1 OnaXuqSmkpnSXzGdYTXixxNHIdBQwt
		$a_01_5 = {5a 4f 69 49 71 6c 56 5a 44 51 6d 41 74 65 4e 47 72 4d 4a 4b 6e 5a 59 76 49 4d 6e 6d 5a 69 53 55 75 4a } //1 ZOiIqlVZDQmAteNGrMJKnZYvIMnmZiSUuJ
		$a_01_6 = {48 7a 78 41 66 55 6c 6a 48 51 6b 6f 6f 55 73 6e 66 6f 75 67 6a 6a 48 69 6e 56 4c 52 5a 65 79 45 68 48 66 6d 75 4a 4e 56 6f 57 } //1 HzxAfUljHQkooUsnfougjjHinVLRZeyEhHfmuJNVoW
		$a_01_7 = {63 44 77 79 67 6f 4e 67 53 4a 67 70 42 6b 6b 6c 6c 6c 4a 79 58 79 7a 6d 4b 48 66 59 6b 76 67 50 54 4f 76 4f 72 73 6b 77 6c } //1 cDwygoNgSJgpBkklllJyXyzmKHfYkvgPTOvOrskwl
		$a_01_8 = {46 54 74 4a 6b 4d 4d 68 50 46 43 42 5a 53 6c 73 42 52 6b 6c 55 67 4d 4d 71 6f 41 48 62 4c 79 71 55 65 } //1 FTtJkMMhPFCBZSlsBRklUgMMqoAHbLyqUe
		$a_01_9 = {51 4a 48 75 68 5a 47 7a 68 44 48 43 75 50 79 42 54 6d 57 74 79 76 6f 75 4a 6f 64 56 7a 6d 59 47 4d 63 55 4a 7a 70 6f 76 56 58 } //1 QJHuhZGzhDHCuPyBTmWtyvouJodVzmYGMcUJzpovVX
		$a_01_10 = {72 72 4c 6c 72 4d 4d 4c 6d 46 59 6f 54 70 71 6c 47 66 4d 73 7a 4b 6a 65 49 75 71 46 6f 6a 6a 55 78 4b 6f 65 6d 47 70 4f 75 4b 69 41 65 56 79 44 46 4f 73 } //1 rrLlrMMLmFYoTpqlGfMszKjeIuqFojjUxKoemGpOuKiAeVyDFOs
		$a_01_11 = {43 47 55 59 52 69 52 51 77 6e 57 73 4e 4f 43 64 78 6f 54 6a 62 56 4f 6b 65 } //1 CGUYRiRQwnWsNOCdxoTjbVOke
		$a_01_12 = {74 68 67 74 4c 54 4b 72 63 5a 75 65 48 77 72 49 54 4f 49 42 74 48 42 4c 49 51 48 72 4c 70 } //1 thgtLTKrcZueHwrITOIBtHBLIQHrLp
		$a_01_13 = {4c 43 54 4f 76 64 6b 42 65 52 68 73 45 6c 44 4a 52 6f 4f 43 51 51 64 6f 47 4d 42 63 } //1 LCTOvdkBeRhsElDJRoOCQQdoGMBc
		$a_01_14 = {6a 67 66 68 5a 65 6c 6d 4c 6e 61 55 63 47 56 68 79 43 49 6f 41 70 48 59 55 59 4f 43 47 5a 45 44 69 65 47 50 6a 43 76 } //1 jgfhZelmLnaUcGVhyCIoApHYUYOCGZEDieGPjCv
		$a_01_15 = {6b 55 51 77 54 43 6c 49 68 42 41 57 4d 68 62 71 6b 59 75 69 71 66 58 58 43 75 78 79 4b 43 59 4c 49 59 48 58 65 55 4f 49 54 } //1 kUQwTClIhBAWMhbqkYuiqfXXCuxyKCYLIYHXeUOIT
		$a_01_16 = {4b 65 4d 58 77 74 78 4e 45 64 49 64 55 6e 73 78 4f 6f 58 7a 6a 4f 71 4c 67 4d 57 71 61 68 73 65 72 6f 57 63 59 58 52 4f 6a 51 77 59 41 66 73 63 67 44 66 } //1 KeMXwtxNEdIdUnsxOoXzjOqLgMWqahseroWcYXROjQwYAfscgDf
		$a_01_17 = {62 50 77 6d 54 42 54 6e 6e 4d 54 66 6d 6b 57 53 45 52 48 63 52 48 42 53 75 78 71 62 } //1 bPwmTBTnnMTfmkWSERHcRHBSuxqb
		$a_01_18 = {44 69 79 66 68 52 71 61 58 59 4c 79 47 75 4f 43 51 43 5a 66 66 56 64 4e 44 67 76 42 6b 71 62 77 69 4d 4f 53 77 } //1 DiyfhRqaXYLyGuOCQCZffVdNDgvBkqbwiMOSw
		$a_01_19 = {4e 46 6f 69 75 4f 65 48 7a 53 68 53 59 4c 66 47 53 7a 65 4a 58 72 46 42 6b 66 68 6b 43 71 6e 45 72 70 6a 67 4a 7a 4a 42 7a } //1 NFoiuOeHzShSYLfGSzeJXrFBkfhkCqnErpjgJzJBz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=4
 
}