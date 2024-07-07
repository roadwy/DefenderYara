
rule TrojanDownloader_O97M_Dridex_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 65 75 72 6f 2d 6f 66 66 69 63 65 2e 6e 65 74 2f 41 77 49 33 75 77 69 77 75 55 36 2e 70 68 70 } //1 https://euro-office.net/AwI3uwiwuU6.php
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 6c 61 6d 69 72 61 67 65 72 65 63 65 70 74 69 6f 6e 2e 63 6f 6d 2e 61 75 2f 41 42 73 38 64 4a 32 5a 4a 33 6a 67 76 30 6e 2e 70 68 70 } //1 https://lamiragereception.com.au/ABs8dJ2ZJ3jgv0n.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Dridex_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 90 02 0e 2c 20 90 02 0f 29 90 00 } //1
		$a_01_1 = {20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 28 28 } //1  = Join(Array(Chr(CLng((
		$a_01_2 = {26 20 43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 57 28 22 50 22 29 29 29 29 } //1 & ChrW(CLng((AscW("P"))))
		$a_03_3 = {2e 43 72 65 61 74 65 20 90 02 17 2c 20 4e 75 6c 6c 2c 20 90 00 } //1
		$a_01_4 = {43 68 72 28 43 4c 6e 67 28 28 41 73 63 28 22 72 22 29 29 29 29 } //1 Chr(CLng((Asc("r"))))
		$a_01_5 = {43 68 72 57 28 43 4c 6e 67 28 28 41 73 63 28 22 74 22 29 29 29 29 } //1 ChrW(CLng((Asc("t"))))
		$a_03_6 = {57 69 74 68 20 47 65 74 4f 62 6a 65 63 74 28 90 02 0f 29 90 00 } //1
		$a_03_7 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0f 2c 20 90 02 0f 2c 20 90 02 0f 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Dridex_SM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {28 53 70 6c 69 74 28 90 02 0f 28 30 29 2c 20 90 02 15 28 4f 61 29 29 29 2c 20 31 29 2c 20 41 5f 6d 69 6e 5f 31 20 26 20 22 5c 22 20 26 20 76 65 67 61 2c 20 67 69 2c 20 67 69 90 00 } //1
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 } //1 URLDownloadToFileA" (
		$a_03_2 = {52 75 6e 20 28 90 02 0f 20 26 20 22 90 00 } //1
		$a_03_3 = {3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 22 51 22 20 26 20 22 23 22 29 90 00 } //1
		$a_03_4 = {3d 20 22 52 22 20 26 20 22 5e 22 90 02 03 49 66 20 90 02 03 20 3d 20 32 20 54 68 65 6e 20 90 02 0f 20 3d 20 22 2b 2b 22 90 00 } //1
		$a_03_5 = {46 6f 72 20 61 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 90 02 0f 29 20 2d 20 4c 42 6f 75 6e 64 28 90 1b 00 29 20 2b 20 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Dridex_SM_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2b 20 43 68 72 28 43 4c 6e 67 28 28 41 73 63 28 22 50 22 29 29 29 29 20 2b 20 43 68 72 28 43 4c 6e 67 28 28 4e 6f 74 } //1 + Chr(CLng((Asc("P")))) + Chr(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 6a 36 4c 55 72 73 68 6f 78 78 66 68 } //1 Debug.Print j6LUrshoxxfh
		$a_01_2 = {69 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 4a 73 74 54 52 59 7a 54 20 26 20 22 52 59 49 56 6e 68 4f 78 45 57 35 55 20 4d 73 4e 7a 59 53 55 6d 6c 4d 41 4e 22 2c 20 63 6e 67 31 47 5a 77 49 53 72 35 2c 20 79 6d 35 78 5f 59 31 4c 5f 55 73 7a 78 20 26 20 22 4e 71 4d 57 38 5f 37 68 6d 55 20 45 39 6d 61 5f 71 51 6f 5f 70 53 71 5f 74 34 34 74 22 29 29 } //1 i = Join(Array(JstTRYzT & "RYIVnhOxEW5U MsNzYSUmlMAN", cng1GZwISr5, ym5x_Y1L_Uszx & "NqMW8_7hmU E9ma_qQo_pSq_t44t"))
		$a_01_3 = {4f 70 65 6e 20 6d 34 65 50 30 5f 64 69 30 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 43 4c 6e 67 28 28 78 6c 56 61 6c 69 64 61 74 65 57 68 6f 6c 65 4e 75 6d 62 65 72 20 4f 72 20 78 6c 4f 75 74 6c 69 6e 65 29 29 } //1 Open m4eP0_di0 For Binary As #CLng((xlValidateWholeNumber Or xlOutline))
		$a_01_4 = {43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 6f 22 29 29 29 29 20 2b 20 43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 63 22 29 29 29 29 20 2b 20 } //1 Chr(CLng((AscW("o")))) + Chr(CLng((AscW("c")))) + 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}