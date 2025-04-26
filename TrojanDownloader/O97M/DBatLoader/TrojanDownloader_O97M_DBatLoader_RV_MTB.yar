
rule TrojanDownloader_O97M_DBatLoader_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/DBatLoader.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 70 6c 70 6c 2c 66 61 6c 73 65 78 68 74 74 70 2e 73 65 6e 64 } //1 http.open"get",plpl,falsexhttp.send
		$a_01_1 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_DBatLoader_RV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/DBatLoader.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 22 74 22 26 22 70 3a 2f 22 26 22 2f 31 34 37 2e 31 32 34 2e 32 31 36 2e 31 31 33 2f } //1 ="t"&"p:/"&"/147.124.216.113/
		$a_01_1 = {68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 70 6c 70 6c 2c 66 61 6c 73 65 78 68 74 74 70 2e 73 65 6e 64 } //1 http.open"get",plpl,falsexhttp.send
		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}