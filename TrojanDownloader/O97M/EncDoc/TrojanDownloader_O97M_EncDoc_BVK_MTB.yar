
rule TrojanDownloader_O97M_EncDoc_BVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 6c 75 6e 22 26 22 65 74 22 26 22 69 6c 65 73 2e 63 6f 6d 2f 55 41 68 22 26 22 62 74 6e 33 70 22 26 22 77 55 64 78 2f 67 6f 68 2e 67 22 26 22 69 22 26 22 66 } //01 00 
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6b 22 26 22 72 69 22 26 22 76 69 61 2e 69 6e 2f 6f 71 79 32 6f 34 6c 6b 2f 67 6f 68 2e 67 22 26 22 69 22 26 22 66 } //00 00 
	condition:
		any of ($a_*)
 
}