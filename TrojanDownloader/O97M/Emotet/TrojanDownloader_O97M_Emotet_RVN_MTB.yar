
rule TrojanDownloader_O97M_Emotet_RVN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 74 65 72 61 6e 67 69 6e 64 6f 6e 65 73 69 61 2e 6f 72 2e 69 64 2f 6c 69 62 72 61 72 69 65 73 2f 6d 38 46 49 72 2f 22 2c 22 } //1 //terangindonesia.or.id/libraries/m8FIr/","
		$a_01_1 = {2f 2f 74 62 61 72 6e 65 73 2e 63 6f 2e 75 6b 2f 74 62 61 72 6e 65 73 5f 63 6f 5f 75 6b 2f 38 61 69 2f 22 2c 22 } //1 //tbarnes.co.uk/tbarnes_co_uk/8ai/","
		$a_01_2 = {2f 2f 74 6f 77 6f 72 6b 73 2e 63 61 2f 70 68 70 6d 79 61 64 6d 69 6e 2f 4f 73 56 71 75 76 65 75 45 42 2f 22 2c 22 } //1 //toworks.ca/phpmyadmin/OsVquveuEB/","
		$a_01_3 = {2f 2f 6b 6f 6b 66 69 6e 61 6e 63 65 2e 6e 6c 2f 77 70 2d 61 64 6d 69 6e 2f 39 39 68 34 6f 46 56 4d 6f 2f 22 2c 22 } //1 //kokfinance.nl/wp-admin/99h4oFVMo/","
		$a_01_4 = {2f 2f 77 6f 72 64 70 72 65 73 73 2e 61 67 72 75 70 65 6d 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 6a 69 6d 6a 7a 75 2f 22 2c 22 } //1 //wordpress.agrupem.com/wp-admin/jimjzu/","
		$a_01_5 = {2f 2f 77 77 77 2e 61 73 65 67 75 72 61 64 6f 73 61 6c 64 69 61 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 6b 65 6c 51 75 6f 74 39 6b 6f 66 55 54 4c 39 30 75 75 45 2f 22 2c 22 } //1 //www.aseguradosaldia.com/wp-content/kelQuot9kofUTL90uuE/","
		$a_01_6 = {2f 2f 66 74 70 2e 6d 65 63 6f 6e 73 65 72 2e 63 6f 6d 2f 62 61 6e 6e 65 72 2f 72 72 4d 6f 63 53 63 72 71 37 2f 22 2c 22 } //1 //ftp.meconser.com/banner/rrMocScrq7/","
		$a_01_7 = {2f 2f 68 61 74 68 61 61 62 65 61 63 68 2e 63 6f 6d 2f 64 6f 63 75 6d 65 6e 74 73 2f 6b 38 38 72 6e 2f 22 2c 22 } //1 //hathaabeach.com/documents/k88rn/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=1
 
}