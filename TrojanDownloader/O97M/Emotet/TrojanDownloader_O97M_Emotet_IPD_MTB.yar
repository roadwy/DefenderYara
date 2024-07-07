
rule TrojanDownloader_O97M_Emotet_IPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.IPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 62 75 6c 6c 64 6f 67 69 72 6f 6e 77 6f 72 6b 73 6c 6c 63 2e 63 6f 6d 2f 74 65 6d 70 2f 72 38 59 41 49 32 6f 39 38 6f 34 6a 30 55 50 6e 2f } //1 ://bulldogironworksllc.com/temp/r8YAI2o98o4j0UPn/
		$a_01_1 = {3a 2f 2f 62 72 75 63 65 6d 75 6c 6b 65 79 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 58 47 58 55 72 46 32 7a 30 49 2f } //1 ://brucemulkey.com/wp-admin/XGXUrF2z0I/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 62 75 64 64 79 6d 6f 72 65 6c 2e 63 6f 6d 2f 63 64 61 72 2f 33 45 67 67 37 73 55 48 54 54 64 38 6b 53 72 46 6a 2f } //1 ://www.buddymorel.com/cdar/3Egg7sUHTTd8kSrFj/
		$a_01_3 = {3a 2f 2f 61 6c 74 75 6e 79 61 70 69 69 6e 73 61 61 74 2e 63 6f 6d 2f 64 61 74 79 75 73 64 74 79 75 61 73 74 62 67 64 61 73 67 2d 32 33 2f 76 4b 63 6b 4b 68 58 31 31 4c 4a 2f } //1 ://altunyapiinsaat.com/datyusdtyuastbgdasg-23/vKckKhX11LJ/
		$a_01_4 = {3a 2f 2f 62 72 65 6e 64 61 6e 63 6c 65 61 72 79 2e 6e 65 74 2f 63 6f 64 65 5f 70 6c 61 79 67 72 6f 75 6e 64 2f 65 33 5a 71 51 35 57 7a 50 42 71 2f } //1 ://brendancleary.net/code_playground/e3ZqQ5WzPBq/
		$a_01_5 = {3a 2f 2f 77 77 77 2e 62 6f 72 6a 61 6c 6e 6f 6f 72 2e 63 6f 6d 2f 65 6e 67 69 6e 65 31 2f 4d 48 48 2f } //1 ://www.borjalnoor.com/engine1/MHH/
		$a_01_6 = {3a 2f 2f 62 6f 7a 7a 6c 69 6e 65 2e 63 6f 6d 2f 63 70 2f 53 47 4f 77 51 6b 41 30 30 78 35 49 78 65 31 34 65 2f } //1 ://bozzline.com/cp/SGOwQkA00x5Ixe14e/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}