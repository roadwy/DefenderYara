
rule TrojanDownloader_O97M_EncDoc_SSTM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSTM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 61 74 61 53 70 61 63 65 90 02 05 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 90 02 05 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 90 05 1f 06 41 2d 5a 61 2d 7a 2e 62 61 74 90 02 06 64 69 72 20 63 3a 5c 26 65 63 68 6f 20 90 00 } //01 00 
		$a_03_1 = {26 53 45 54 20 90 02 16 3d 68 65 6c 6c 20 2d 65 26 65 63 68 6f 90 00 } //01 00 
		$a_03_2 = {65 63 68 6f 20 90 02 80 26 73 74 61 72 74 2f 42 20 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}