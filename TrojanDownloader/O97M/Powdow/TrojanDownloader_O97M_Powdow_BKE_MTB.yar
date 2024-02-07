
rule TrojanDownloader_O97M_Powdow_BKE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 20 73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 35 } //01 00  bypass stARt`-slE`Ep 25
		$a_01_1 = {27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  'loadFile')
		$a_03_2 = {27 2b 27 2f 90 01 02 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 90 00 } //01 00 
		$a_01_3 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 61 70 66 37 6c 66 72 } //01 00  ttps://tinyurl.com/yapf7lfr
		$a_01_4 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 31 68 41 6e 78 79 79 } //00 00  ttps://cutt.ly/1hAnxyy
	condition:
		any of ($a_*)
 
}