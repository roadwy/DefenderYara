
rule TrojanDownloader_O97M_EncDoc_SSTM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSTM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 61 74 61 53 70 61 63 65 [0-05] 57 73 63 72 69 70 74 2e 53 68 65 6c 6c [0-05] 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 90 05 1f 06 41 2d 5a 61 2d 7a 2e 62 61 74 [0-06] 64 69 72 20 63 3a 5c 26 65 63 68 6f 20 } //1
		$a_03_1 = {26 53 45 54 20 [0-16] 3d 68 65 6c 6c 20 2d 65 26 65 63 68 6f } //1
		$a_03_2 = {65 63 68 6f 20 [0-80] 26 73 74 61 72 74 2f 42 20 25 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}