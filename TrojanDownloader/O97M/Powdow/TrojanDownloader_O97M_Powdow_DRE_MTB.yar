
rule TrojanDownloader_O97M_Powdow_DRE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DRE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 65 6e 28 4c 65 66 74 28 79 79 74 79 79 2c 20 6b 6b 29 29 } //1 Len(Left(yytyy, kk))
		$a_01_1 = {4c 65 66 74 28 79 79 74 79 79 2c 20 34 20 2d 20 33 29 } //1 Left(yytyy, 4 - 3)
		$a_01_2 = {28 52 61 6e 67 65 28 22 44 31 30 31 22 29 29 } //1 (Range("D101"))
		$a_01_3 = {28 52 61 6e 67 65 28 22 44 31 30 30 22 29 29 } //1 (Range("D100"))
		$a_01_4 = {2e 6d 64 6c 66 70 65 28 42 4a 64 68 46 7a 76 42 5a 54 66 57 54 44 70 4a 20 2b 20 74 4c 78 41 57 55 79 62 6d 58 76 76 42 63 67 47 45 54 29 } //1 .mdlfpe(BJdhFzvBZTfWTDpJ + tLxAWUybmXvvBcgGET)
		$a_01_5 = {41 55 76 72 6b 6b 2e 54 65 78 74 } //1 AUvrkk.Text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}