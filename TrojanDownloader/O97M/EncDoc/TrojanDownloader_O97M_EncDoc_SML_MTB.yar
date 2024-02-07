
rule TrojanDownloader_O97M_EncDoc_SML_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 74 63 68 73 2e 63 6f 6d 2e 62 72 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://btchs.com.br/ds/161120.gif
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 75 61 65 75 62 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://uaeub.com/ds/161120.gif
		$a_01_2 = {68 74 74 70 3a 2f 2f 69 2e 73 66 75 2e 65 64 75 2e 70 68 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  http://i.sfu.edu.ph/ds/161120.gif
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 62 65 6d 6f 6a 6f 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://bemojo.com/ds/161120.gif
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 6d 79 73 63 61 70 65 2e 69 6e 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://myscape.in/ds/161120.gif
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 61 6e 68 69 69 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://anhii.com/ds/161120.gif
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 67 61 73 70 65 65 2e 69 6e 66 6f 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://gaspee.info/ds/161120.gif
		$a_01_7 = {68 74 74 70 73 3a 2f 2f 69 6b 6b 6f 6e 2e 70 6b 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://ikkon.pk/ds/161120.gif
		$a_01_8 = {68 74 74 70 73 3a 2f 2f 61 6c 70 69 6e 65 2e 6b 7a 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://alpine.kz/ds/161120.gif
		$a_01_9 = {68 74 74 70 73 3a 2f 2f 6d 6f 65 67 69 66 74 73 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://moegifts.com/ds/161120.gif
		$a_01_10 = {68 74 74 70 3a 2f 2f 63 61 72 67 6f 68 6c 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  http://cargohl.com/ds/161120.gif
		$a_01_11 = {68 74 74 70 3a 2f 2f 69 70 70 70 2e 63 6f 2e 7a 77 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  http://ippp.co.zw/ds/161120.gif
		$a_01_12 = {49 49 43 43 43 43 49 } //00 00  IICCCCI
	condition:
		any of ($a_*)
 
}