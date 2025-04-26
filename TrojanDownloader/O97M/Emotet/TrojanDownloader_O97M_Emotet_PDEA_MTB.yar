
rule TrojanDownloader_O97M_Emotet_PDEA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDEA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 66 61 69 73 6f 6e 66 69 6c 6d 73 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 35 64 73 7a 75 63 38 6d 4d 53 41 34 53 30 57 39 2f } //1 ://faisonfilms.com/wp-includes/5dszuc8mMSA4S0W9/
		$a_01_1 = {3a 2f 2f 74 6f 70 76 69 70 65 73 63 6f 72 74 73 63 6c 75 62 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 65 79 41 35 38 72 70 46 7a 65 35 47 71 2f } //1 ://topvipescortsclub.com/assets/eyA58rpFze5Gq/
		$a_01_2 = {3a 2f 2f 6d 65 63 6f 6e 73 65 72 2e 63 6f 6d 2f 62 61 6e 6e 65 72 2f 74 50 38 70 2f } //1 ://meconser.com/banner/tP8p/
		$a_01_3 = {3a 2f 2f 77 70 2e 65 72 79 61 7a 2e 6e 65 74 2f 62 61 79 61 72 31 2f 47 51 53 4d 73 71 6a 41 32 2f } //1 ://wp.eryaz.net/bayar1/GQSMsqjA2/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}