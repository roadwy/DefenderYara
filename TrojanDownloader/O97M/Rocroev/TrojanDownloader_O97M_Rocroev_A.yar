
rule TrojanDownloader_O97M_Rocroev_A{
	meta:
		description = "TrojanDownloader:O97M/Rocroev.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 35 2e 31 39 39 2e 31 36 35 2e 32 33 39 2f 6d 61 72 63 68 32 33 2e 70 68 70 } //1 http://5.199.165.239/march23.php
		$a_03_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 90 02 0f 20 26 20 22 90 02 0f 5c 90 02 0f 2e 63 6f 6d 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}