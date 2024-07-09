
rule TrojanDownloader_O97M_EncDoc_PKSY_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKSY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 63 65 6e 74 75 72 79 70 61 70 65 72 73 2e 63 6f 6d 2f 63 6c 61 73 73 65 73 2f 70 57 47 39 4f 69 57 30 35 30 56 4c 53 73 2f 22 2c 22 } //1 ://www.centurypapers.com/classes/pWG9OiW050VLSs/","
		$a_01_1 = {3a 2f 2f 62 72 6f 6f 6b 6c 79 6e 73 65 72 76 69 63 65 73 67 72 6f 75 70 2e 63 6f 6d 2f 69 6e 63 2f 70 49 79 75 4d 2f 22 2c 22 } //1 ://brooklynservicesgroup.com/inc/pIyuM/","
		$a_01_2 = {3a 2f 2f 63 68 61 69 6e 61 6e 64 70 79 6c 65 2e 63 6f 6d 2f 4f 6c 64 2f 55 6c 66 47 47 4e 4e 36 78 62 61 75 2f 22 2c 22 } //1 ://chainandpyle.com/Old/UlfGGNN6xbau/","
		$a_01_3 = {3a 2f 2f 63 68 61 72 6d 73 6c 6f 76 65 73 70 65 6c 6c 73 2e 63 6f 6d 2f 79 74 2d 61 73 73 65 74 73 2f 5a 63 43 4e 4a 49 31 42 2f 22 2c 22 } //1 ://charmslovespells.com/yt-assets/ZcCNJI1B/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_PKSY_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKSY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 [0-20] 3a 2f 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2e [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-50] 2f 22 2c 22 [0-05] 3a 2f 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2e [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-50] 2f 22 2c 22 [0-05] 3a 2f 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2e [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-20] 2f [0-05] 22 26 22 [0-05] 22 26 22 [0-50] 2f 22 2c 22 [0-05] 3a 2f 2f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}