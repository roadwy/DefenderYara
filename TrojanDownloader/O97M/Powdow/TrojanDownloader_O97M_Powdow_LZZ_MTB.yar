
rule TrojanDownloader_O97M_Powdow_LZZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.LZZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 65 72 5e 73 68 65 5e 6c 5e 6c } //01 00  wer^she^l^l
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  ('Down'+'loadFile')
		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 36 76 6c 67 68 76 75 } //01 00  ttps://tinyurl.com/y6vlghvu
		$a_01_3 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } //00 00  (nEw-oB`jecT
	condition:
		any of ($a_*)
 
}