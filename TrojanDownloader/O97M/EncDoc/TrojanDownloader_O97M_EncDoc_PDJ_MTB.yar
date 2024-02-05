
rule TrojanDownloader_O97M_EncDoc_PDJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 27 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 27 20 2b 20 27 6c 43 62 27 3b 20 24 63 33 3d 27 29 27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 6e 6f 6f 73 2f 6b 74 2e 64 65 6e 69 6b 2f 2f 3a 70 74 74 68 27 27 28 } //01 00 
		$a_01_1 = {3d 27 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 27 20 2b 20 27 6c 43 62 27 3b 20 24 63 33 3d 27 29 27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 65 72 69 66 2f 6b 74 2e 64 65 6e 69 6b 2f 2f 3a 70 74 74 68 27 27 28 } //00 00 
	condition:
		any of ($a_*)
 
}