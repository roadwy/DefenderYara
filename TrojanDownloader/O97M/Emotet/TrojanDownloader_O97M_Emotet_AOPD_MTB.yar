
rule TrojanDownloader_O97M_Emotet_AOPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AOPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 62 6f 75 63 68 65 72 69 65 2d 74 68 6f 6c 6c 61 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 51 2f } //01 00  ://www.boucherie-thollas.com/wp-content/Q/
		$a_01_1 = {3a 2f 2f 77 77 77 2e 77 65 6e 6e 65 32 34 2e 6b 65 75 72 69 67 6f 6e 6c 69 6e 65 35 32 2e 6e 6c 2f 63 67 69 2d 62 69 6e 2f 46 73 48 51 33 6e 64 6b 5a 62 2f } //01 00  ://www.wenne24.keurigonline52.nl/cgi-bin/FsHQ3ndkZb/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 73 75 70 65 72 73 61 6e 6d 75 74 66 61 6b 2e 63 6f 6d 2f 54 65 6d 70 6c 61 74 65 2f 66 4d 68 37 6e 75 2f } //01 00  ://www.supersanmutfak.com/Template/fMh7nu/
		$a_01_3 = {3a 2f 2f 77 77 77 2e 76 65 6e 65 73 73 6f 72 69 2e 63 6f 6d 2f 70 63 39 37 73 51 50 71 66 63 56 61 6d 34 45 55 74 63 55 35 2f } //00 00  ://www.venessori.com/pc97sQPqfcVam4EUtcU5/
	condition:
		any of ($a_*)
 
}