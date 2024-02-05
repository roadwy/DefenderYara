
rule TrojanDownloader_O97M_EncDoc_NEV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.NEV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 69 70 2e 64 69 67 69 74 61 6c 2f 31 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 63 61 66 44 4b 52 76 5c 49 49 58 62 65 56 75 5c 51 6b 70 78 6e 54 62 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}