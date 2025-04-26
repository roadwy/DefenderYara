
rule TrojanDownloader_O97M_DBatLoader_VRD_MTB{
	meta:
		description = "TrojanDownloader:O97M/DBatLoader.VRD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 22 20 26 20 22 70 3a 2f 22 20 26 20 22 2f 38 37 2e 31 32 30 2e 31 31 33 2e 39 31 2f 69 6d 61 67 65 } //1 = "t" & "p:/" & "/87.120.113.91/image
		$a_01_1 = {68 74 74 70 2e 6f 70 65 6e 22 67 65 74 22 2c 70 6c 70 6c 2c 66 61 6c 73 65 78 68 74 74 70 2e 73 65 6e 64 } //1 http.open"get",plpl,falsexhttp.send
		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}