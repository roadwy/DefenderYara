
rule TrojanDownloader_O97M_Emotet_PDW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 65 6e 74 72 6f 62 69 6c 69 6e 67 75 65 6c 6f 73 70 69 6e 6f 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 56 72 67 7a 57 54 2f } //1 ://centrobilinguelospinos.com/wp-admin/VrgzWT/
		$a_01_1 = {3a 2f 2f 62 6f 61 72 64 69 6e 67 73 63 68 6f 6f 6c 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f 62 61 63 6b 75 70 2f 43 74 4d 52 35 59 69 2f } //1 ://boardingschoolsoftware.com/backup/CtMR5Yi/
		$a_01_2 = {3a 2f 2f 62 73 61 2e 69 61 69 6e 2d 6a 65 6d 62 65 72 2e 61 63 2e 69 64 2f 61 73 73 65 74 2f 78 30 68 4d 77 4f 50 56 70 6b 51 53 4e 6f 53 38 57 43 4e 2f } //1 ://bsa.iain-jember.ac.id/asset/x0hMwOPVpkQSNoS8WCN/
		$a_01_3 = {3a 2f 2f 63 74 68 61 2e 75 79 2f 63 67 69 2d 62 69 6e 2f 7a 47 68 76 5a 4c 71 36 6b 53 56 31 4c 31 56 69 2f } //1 ://ctha.uy/cgi-bin/zGhvZLq6kSV1L1Vi/
		$a_01_4 = {3a 2f 2f 64 65 73 63 6f 6e 74 61 64 6f 72 2e 63 6f 6d 2e 62 72 2f 63 73 73 2f 71 35 6e 72 47 36 75 61 2f } //1 ://descontador.com.br/css/q5nrG6ua/
		$a_01_5 = {3a 2f 2f 6c 65 74 65 61 2e 65 75 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 33 47 67 46 34 6d 69 46 5a 54 71 39 2f } //1 ://letea.eu/wp-content/3GgF4miFZTq9/
		$a_01_6 = {3a 2f 2f 71 75 6f 63 74 6f 61 6e 2e 63 31 2e 62 69 7a 2f 77 70 2d 61 64 6d 69 6e 2f 6a 38 5a 75 2f } //1 ://quoctoan.c1.biz/wp-admin/j8Zu/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}