
rule TrojanDownloader_O97M_EncDoc_DTS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.DTS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 65 63 66 69 6c 65 32 34 2e 74 6f 70 2f 6b 64 33 32 33 6a 61 73 64 2e 70 68 70 } //01 00 
		$a_01_1 = {43 3a 5c 65 6f 4a 58 4b 77 58 5c 74 73 56 43 55 47 4b 5c 74 65 4d 4f 6a 4d 51 2e 64 6c 6c } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}