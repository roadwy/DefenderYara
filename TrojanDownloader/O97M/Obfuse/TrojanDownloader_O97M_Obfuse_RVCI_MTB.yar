
rule TrojanDownloader_O97M_Obfuse_RVCI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 22 36 38 37 34 22 27 22 68 74 74 70 22 70 61 72 74 32 3d 22 37 34 37 30 33 61 32 66 32 66 22 27 22 3a 5c 5c 22 70 61 72 74 33 3d 22 33 34 33 35 32 65 33 31 33 34 33 37 22 27 22 34 35 2e 31 34 37 22 70 61 72 74 34 3d 22 32 65 33 32 33 33 33 31 32 65 33 31 33 39 33 35 32 66 36 64 37 33 37 37 36 66 37 32 36 34 36 34 32 65 36 35 37 38 36 35 22 } //1 ="6874"'"http"part2="74703a2f2f"'":\\"part3="34352e313437"'"45.147"part4="2e3233312e3139352f6d73776f7264642e657865"
		$a_01_1 = {3d 72 65 73 75 6c 74 26 63 68 72 28 22 26 68 22 26 6d 69 64 28 68 65 78 73 74 72 69 6e 67 2c 69 2c 32 29 29 6e 65 78 74 } //1 =result&chr("&h"&mid(hexstring,i,2))next
		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 29 } //1 autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}