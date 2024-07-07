
rule TrojanDownloader_O97M_Powdow_BKD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_1 = {27 6c 6f 61 64 46 69 6c 65 27 29 } //1 'loadFile')
		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 62 68 78 76 78 67 64 } //1 ttps://tinyurl.com/ybhxvxgd
		$a_01_3 = {27 2b 27 2f 74 63 22 26 43 48 41 52 28 34 36 29 26 22 73 63 72 27 29 } //1 '+'/tc"&CHAR(46)&"scr')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_BKD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_1 = {27 6c 6f 61 64 46 69 6c 65 27 29 } //1 'loadFile')
		$a_03_2 = {27 2b 27 2f 90 01 02 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 90 00 } //1
		$a_01_3 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 46 68 44 76 36 33 31 } //1 ttps://cutt.ly/FhDv631
		$a_01_4 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 61 70 6f 38 70 78 73 } //1 ttps://tinyurl.com/yapo8pxs
		$a_01_5 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 38 62 63 79 6c 79 } //1 ttps://tinyurl.com/y8bcyly
		$a_01_6 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 62 6a 35 70 6d 6e 66 } //1 ttps://tinyurl.com/ybj5pmnf
		$a_01_7 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 39 75 37 77 34 6a 6a } //1 ttps://tinyurl.com/y9u7w4jj
		$a_01_8 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 66 68 41 6d 6a 4c 33 } //1 ttps://cutt.ly/fhAmjL3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}