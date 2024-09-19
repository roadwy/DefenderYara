
rule Trojan_Win32_Neoreblamy_ASF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {45 66 79 65 78 48 46 41 74 73 4a 70 56 6b 74 4d 51 45 47 4e 56 62 55 62 75 78 55 61 57 50 } //1 EfyexHFAtsJpVktMQEGNVbUbuxUaWP
		$a_01_1 = {42 72 52 6d 58 46 72 56 68 69 4d 42 62 72 44 47 46 49 78 56 43 67 7a 6b 70 69 66 41 } //1 BrRmXFrVhiMBbrDGFIxVCgzkpifA
		$a_01_2 = {58 55 6f 66 4b 6f 58 42 46 4a 61 48 54 42 47 6c 44 52 77 54 64 43 55 6c 4b 72 53 43 43 6e 48 6a 4b 41 } //1 XUofKoXBFJaHTBGlDRwTdCUlKrSCCnHjKA
		$a_01_3 = {5a 74 4e 64 64 46 50 76 50 53 4a 42 76 51 74 4f 7a 58 6f 77 4f 54 63 4a 69 47 78 65 58 } //1 ZtNddFPvPSJBvQtOzXowOTcJiGxeX
		$a_01_4 = {77 6d 56 63 6b 47 6b 63 77 75 58 75 50 56 74 44 41 5a 4e 68 6b 47 62 52 51 64 67 63 76 4a } //1 wmVckGkcwuXuPVtDAZNhkGbRQdgcvJ
		$a_01_5 = {56 59 55 78 76 73 62 66 6a 63 77 53 57 6b 70 49 51 57 53 6f 47 58 66 66 76 74 48 78 } //1 VYUxvsbfjcwSWkpIQWSoGXffvtHx
		$a_01_6 = {77 69 4e 49 48 52 55 42 74 70 6b 41 71 51 76 76 44 57 55 73 6d 49 43 57 77 4b 7a 49 6a 42 } //1 wiNIHRUBtpkAqQvvDWUsmICWwKzIjB
		$a_01_7 = {6d 6c 77 6f 45 4b 43 53 53 68 66 57 6a 4e 53 4a 4c 6b 62 4c 47 52 67 66 42 43 4e 54 } //1 mlwoEKCSShfWjNSJLkbLGRgfBCNT
		$a_01_8 = {68 65 71 55 78 6e 75 4c 76 44 57 72 4d 61 56 4c 44 59 61 55 75 6f 50 6c 61 7a 62 6b 47 47 4e 53 6f 76 } //1 heqUxnuLvDWrMaVLDYaUuoPlazbkGGNSov
		$a_01_9 = {4b 4a 53 44 46 56 70 70 48 77 4f 4a 59 71 4d 4c 58 75 70 6d 53 4d 4e 4b 77 48 6f 58 53 67 50 52 4d 61 } //1 KJSDFVppHwOJYqMLXupmSMNKwHoXSgPRMa
		$a_01_10 = {71 43 59 62 66 46 59 6d 47 59 49 73 41 64 7a 53 69 6a 55 6d 6e 64 44 4b 72 76 77 52 70 48 76 46 56 6b 66 } //1 qCYbfFYmGYIsAdzSijUmndDKrvwRpHvFVkf
		$a_01_11 = {4a 55 73 50 53 6d 41 65 65 57 76 47 42 4b 79 71 47 59 43 44 55 4f 6d 65 78 50 4a 4c 68 65 46 42 } //1 JUsPSmAeeWvGBKyqGYCDUOmexPJLheFB
		$a_01_12 = {78 78 75 5a 71 58 56 78 63 50 69 4c 58 76 4d 51 53 71 70 41 48 6e 62 63 45 4f 48 79 62 55 72 58 58 72 4a 54 54 67 4a 6a 49 43 65 6f 61 44 78 51 71 74 50 } //1 xxuZqXVxcPiLXvMQSqpAHnbcEOHybUrXXrJTTgJjICeoaDxQqtP
		$a_01_13 = {51 6e 54 59 4e 52 68 42 6b 67 68 75 51 63 4d 67 51 65 4d 68 63 63 5a 79 4c 72 72 69 59 75 6a 77 7a 74 52 6a 51 73 78 55 6c } //1 QnTYNRhBkghuQcMgQeMhccZyLrriYujwztRjQsxUl
		$a_01_14 = {79 67 4f 52 7a 43 6f 4d 76 56 57 4f 52 78 49 56 59 47 54 6e 65 6d 53 69 51 51 4d 64 68 43 71 61 52 4c 6f 62 6e } //1 ygORzCoMvVWORxIVYGTnemSiQQMdhCqaRLobn
		$a_01_15 = {78 7a 61 6b 48 58 54 70 65 48 73 77 51 66 74 61 46 74 76 77 4c 6c 46 73 72 67 52 49 61 70 6e 46 4f } //1 xzakHXTpeHswQftaFtvwLlFsrgRIapnFO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}