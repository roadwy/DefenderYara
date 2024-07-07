
rule TrojanDownloader_O97M_Tnega_SA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6d 20 3d 20 22 68 74 74 70 3a 2f 2f 63 72 61 67 68 6f 70 70 65 72 73 2e 69 63 75 2f 4f 72 64 65 72 2e 6a 70 67 7c 7c 7c 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 } //2 Dm = "http://craghoppers.icu/Order.jpg|||msxml2.xmlhttp
		$a_01_1 = {44 6d 20 3d 20 22 68 74 74 70 3a 2f 2f 6d 6f 76 65 69 73 2d 73 63 68 75 73 74 65 72 2d 63 6f 6d 2e 67 61 2f 4f 72 64 65 72 2e 6a 70 67 7c 7c 7c 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 } //2 Dm = "http://moveis-schuster-com.ga/Order.jpg|||msxml2.xmlhttp
		$a_01_2 = {53 65 74 20 78 6d 6c 48 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 56 42 29 } //1 Set xmlHttp = CreateObject(VB)
		$a_01_3 = {67 20 3d 20 53 70 6c 69 74 28 44 6d 2c 20 22 7c 7c 7c 22 29 } //1 g = Split(Dm, "|||")
		$a_01_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 73 74 72 55 52 4c } //1 .Open "get", strURL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}