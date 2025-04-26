
rule TrojanDownloader_O97M_Powdow_TTZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TTZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 ('Down'+'loadFile')
		$a_01_2 = {22 49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 76 68 6d 39 4b 57 58 27 2c 27 70 64 } //1 "Invoke"('https://cutt.ly/vhm9KWX','pd
		$a_01_3 = {22 49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 4e 68 51 75 39 37 49 27 2c 27 70 64 } //1 "Invoke"('https://cutt.ly/NhQu97I','pd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}