
rule TrojanDownloader_O97M_Powdow_TMP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TMP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {77 65 72 5e 73 68 65 } //1 wer^she
		$a_01_1 = {2d 77 20 31 20 73 74 41 52 74 60 2d 73 } //1 -w 1 stARt`-s
		$a_03_2 = {4d 6f 76 65 2d 49 74 65 6d 20 22 70 64 [0-15] 62 61 74 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 65 60 6e 56 3a 54 60 45 4d 50 22 } //1
		$a_01_3 = {2d 77 20 31 20 73 74 41 52 74 60 2d 73 6c 45 60 45 70 } //1 -w 1 stARt`-slE`Ep
		$a_01_4 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 70 64 } //1 Remove-Item -Path pd
		$a_01_5 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_6 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 ('Down'+'loadFile')
		$a_03_7 = {22 49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f [0-10] 27 2c 27 70 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}