
rule Trojan_Win64_Emotet_MM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 54 73 7a 7a 50 4b 6f 71 4e 58 54 50 66 52 } //10 ATszzPKoqNXTPfR
		$a_01_1 = {42 65 58 46 73 41 47 55 4f 6d 61 51 77 66 4a 43 57 79 44 7a 6d 7a 4e } //1 BeXFsAGUOmaQwfJCWyDzmzN
		$a_01_2 = {43 43 71 6d 75 71 49 4b 56 57 78 53 66 70 66 } //1 CCqmuqIKVWxSfpf
		$a_01_3 = {41 46 41 43 45 58 71 77 55 74 48 7a 74 75 77 6d 47 62 51 77 4e } //10 AFACEXqwUtHztuwmGbQwN
		$a_01_4 = {41 4e 47 4d 57 6b 69 63 74 63 6d } //1 ANGMWkictcm
		$a_01_5 = {41 65 47 46 47 46 41 6b 74 4a 69 73 72 66 71 6d } //1 AeGFGFAktJisrfqm
		$a_01_6 = {78 55 75 44 51 4e 70 45 42 6f 4b 68 46 49 4d 53 62 } //10 xUuDQNpEBoKhFIMSb
		$a_01_7 = {79 78 61 7a 62 74 6e 49 66 74 79 46 55 56 46 4e } //1 yxazbtnIftyFUVFN
		$a_01_8 = {7a 44 49 54 7a 71 71 70 6d 73 67 68 48 4f 51 46 58 6e 48 55 53 67 74 6a } //1 zDITzqqpmsghHOQFXnHUSgtj
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=12
 
}