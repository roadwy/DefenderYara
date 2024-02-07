
rule TrojanDownloader_O97M_Emotet_MMPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.MMPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 72 6f 61 64 77 61 79 6d 65 6c 6f 64 79 2e 63 61 2f 73 74 61 74 73 2f 44 56 59 77 34 51 70 63 66 31 79 6f 2f } //01 00  broadwaymelody.ca/stats/DVYw4Qpcf1yo/
		$a_01_1 = {62 69 67 69 64 65 61 73 2e 63 6f 6d 2e 61 75 2f 69 6d 61 67 65 73 2f 77 35 46 4c 41 4a 50 6d 76 62 6b 39 2f } //01 00  bigideas.com.au/images/w5FLAJPmvbk9/
		$a_01_2 = {77 65 62 73 74 72 65 61 6d 2e 6a 70 2f 64 69 65 64 2d 77 69 6e 67 2f 6f 4f 7a 66 56 63 2f } //01 00  webstream.jp/died-wing/oOzfVc/
		$a_01_3 = {32 34 68 62 69 6e 68 70 68 75 6f 63 2e 63 6f 6d 2e 76 6e 2f 64 61 74 61 2f 46 6f 73 5a 35 47 46 53 36 50 50 33 6b 73 68 62 56 6e 37 2f } //01 00  24hbinhphuoc.com.vn/data/FosZ5GFS6PP3kshbVn7/
		$a_01_4 = {62 6d 6e 65 67 6f 63 69 6f 73 69 6e 6d 6f 62 69 6c 69 61 72 69 6f 73 2e 63 6f 6d 2e 61 72 2f 63 67 69 2d 62 69 6e 2f 62 69 6a 68 41 4d 57 52 65 41 30 48 33 69 38 61 2f } //01 00  bmnegociosinmobiliarios.com.ar/cgi-bin/bijhAMWReA0H3i8a/
		$a_01_5 = {62 69 6e 6e 75 72 79 65 74 69 6b 64 61 6e 69 73 6d 61 6e 6c 69 6b 2e 63 6f 6d 2e 74 72 2f 69 6d 61 67 65 73 2f 56 62 79 74 79 4f 46 74 53 31 4d 46 2f } //01 00  binnuryetikdanismanlik.com.tr/images/VbytyOFtS1MF/
		$a_01_6 = {62 72 65 65 64 69 64 2e 6e 6c 2f 63 67 69 2d 62 69 6e 2f 61 43 62 74 2f } //00 00  breedid.nl/cgi-bin/aCbt/
	condition:
		any of ($a_*)
 
}