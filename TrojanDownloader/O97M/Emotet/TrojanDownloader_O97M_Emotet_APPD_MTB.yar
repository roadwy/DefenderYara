
rule TrojanDownloader_O97M_Emotet_APPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.APPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 65 6c 62 61 63 6f 6c 6c 65 70 61 72 61 64 69 73 6f 2e 69 74 2f 77 70 2d 61 64 6d 69 6e 2f 5a 78 51 44 4f 6f 6a 54 5a 4e 50 30 73 4b 43 69 48 6f 2f } //1 ://elbacolleparadiso.it/wp-admin/ZxQDOojTZNP0sKCiHo/
		$a_01_1 = {3a 2f 2f 75 6c 74 72 61 64 72 6f 6e 65 61 66 72 69 63 61 2e 63 6f 6d 2f 43 6f 6e 74 65 6e 75 5f 55 53 2f 35 35 52 50 43 6b 4b 4e 6c 2f } //1 ://ultradroneafrica.com/Contenu_US/55RPCkKNl/
		$a_01_2 = {3a 2f 2f 76 69 74 65 6e 65 74 74 65 73 65 72 76 69 63 65 2e 63 6f 6d 2f 66 75 6e 63 74 69 6f 6e 73 2f 35 35 55 37 4e 2f } //1 ://vitenetteservice.com/functions/55U7N/
		$a_01_3 = {3a 2f 2f 6c 61 69 6d 65 73 6e 61 6d 61 69 2e 6c 74 2f 56 61 69 7a 64 6f 2f 54 73 5a 41 6b 6b 51 78 71 64 6d 56 2f } //1 ://laimesnamai.lt/Vaizdo/TsZAkkQxqdmV/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}