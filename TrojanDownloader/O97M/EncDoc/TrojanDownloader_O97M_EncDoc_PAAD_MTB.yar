
rule TrojanDownloader_O97M_EncDoc_PAAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6d 6f 64 75 6c 65 31 22 73 75 62 6d 61 63 68 69 6e 65 28 29 } //1 vb_name="module1"submachine()
		$a_03_1 = {76 61 6c 75 65 26 72 61 6e 67 65 28 22 [0-7f] 22 29 2e 76 61 6c 75 65 26 72 61 6e 67 65 28 22 [0-7f] 22 29 2e 76 61 6c 75 65 66 69 6c 65 6f 75 74 2e 77 72 69 74 65 73 74 72 74 65 78 74 66 69 6c 65 6f 75 74 2e 63 } //1
		$a_03_2 = {3d 73 68 65 6c 6c 28 22 77 73 63 72 69 70 74 61 70 69 68 61 6e 64 6c 65 72 2e 6a 73 22 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 72 61 6e 67 65 28 22 [0-7f] 22 29 2e 76 61 6c 75 65 3d 22 22 72 61 6e 67 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}