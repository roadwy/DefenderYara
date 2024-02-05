
rule TrojanDownloader_O97M_EncDoc_RVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 73 74 61 6c 6c 65 72 22 29 } //01 00 
		$a_01_1 = {70 56 78 44 44 65 74 7a 70 2e 49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74 20 22 68 74 74 70 3a 2f 2f 38 34 2e 33 32 2e 31 38 38 2e 31 34 31 2f 22 } //01 00 
		$a_01_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 31 22 29 2e 55 6e 70 72 6f 74 65 63 74 20 22 31 32 33 34 35 36 22 } //00 00 
	condition:
		any of ($a_*)
 
}