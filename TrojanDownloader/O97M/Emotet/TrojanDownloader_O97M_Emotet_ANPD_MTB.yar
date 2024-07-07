
rule TrojanDownloader_O97M_Emotet_ANPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ANPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6e 61 74 61 79 61 6b 69 6d 2e 63 6f 6d 2f 5f 68 6c 61 6d 2f 4f 62 37 38 70 36 53 78 4d 4e 6f 6e 6f 66 47 2f } //1 ://natayakim.com/_hlam/Ob78p6SxMNonofG/
		$a_01_1 = {3a 2f 2f 77 65 70 6c 75 67 2e 63 6f 6d 2f 64 6f 6d 2f 4c 66 64 65 56 38 48 34 5a 79 31 79 4c 46 52 56 2f } //1 ://weplug.com/dom/LfdeV8H4Zy1yLFRV/
		$a_01_2 = {3a 2f 2f 6d 61 72 74 69 6e 6d 69 63 68 61 6c 65 6b 2e 63 6f 6d 2f 5f 73 75 62 2f 47 31 51 4b 77 45 59 50 62 74 2f } //1 ://martinmichalek.com/_sub/G1QKwEYPbt/
		$a_01_3 = {3a 2f 2f 77 69 6e 6b 65 6c 73 75 70 70 6c 79 2e 6e 6c 2f 63 67 69 2d 62 69 6e 2f 79 6b 79 79 47 51 43 36 55 49 58 72 45 74 43 74 33 37 2f } //1 ://winkelsupply.nl/cgi-bin/ykyyGQC6UIXrEtCt37/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}