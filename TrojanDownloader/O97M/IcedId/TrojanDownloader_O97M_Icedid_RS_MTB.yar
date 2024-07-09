
rule TrojanDownloader_O97M_Icedid_RS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Icedid.RS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 22 20 2b 20 [0-10] 20 2b 20 22 65 6c 6c 22 29 2e 72 75 6e 28 [0-10] 29 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_03_1 = {20 3d 20 56 42 41 2e 53 70 6c 69 74 28 [0-0a] 28 22 6c 6d 74 68 2e 6e 69 7c 6d 6f 63 2e 6e 69 7c 65 78 65 2e 61 74 68 73 6d 22 29 2c 20 22 7c 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}