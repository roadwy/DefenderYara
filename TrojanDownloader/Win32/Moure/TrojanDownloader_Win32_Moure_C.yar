
rule TrojanDownloader_Win32_Moure_C{
	meta:
		description = "TrojanDownloader:Win32/Moure.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 0c 3d 27 7a e1 eb e2 1d 33 d2 99 94 e4 77 61 74 14 6f 82 35 de 0c 00 ef a7 0d 50 5a 95 76 66 4a 14 6f 82 3c 6f 6e d5 1b dd 07 ad 2b 42 20 54 } //1
		$a_01_1 = {d8 ab 75 2c 19 22 54 2d df 65 dc ab 65 dc 1b 66 38 52 e0 cb 1d ab 75 dc 2f 97 24 71 ab 24 a3 23 65 28 1b e6 56 39 1b 65 cc 53 34 ab 24 b7 23 65 28 70 df 55 28 df 35 94 05 60 00 a5 e0 54 0b a5 } //1
		$a_01_2 = {7c 53 59 53 57 4f 57 16 14 7c 53 56 43 48 4f 53 54 0e 45 58 45 00 00 00 7c 53 59 53 54 45 4d 13 12 7c 57 55 41 55 43 4c 54 0e 45 58 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}