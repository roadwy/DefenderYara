
rule TrojanDownloader_O97M_EncDoc_PKEC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKEC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 73 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 62 61 74 22 2c 20 54 72 75 65 29 } //01 00 
		$a_01_1 = {6d 73 68 74 61 20 22 22 68 74 74 70 73 3a 2f 2f 73 6b 79 6e 65 74 78 2e 63 6f 6d 2e 62 72 2f 63 76 63 2e 68 74 6d 6c } //01 00 
		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 2e 6c 79 2f 33 6f 4f 6c 63 75 45 } //00 00 
	condition:
		any of ($a_*)
 
}