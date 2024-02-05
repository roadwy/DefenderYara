
rule TrojanDownloader_O97M_EncDoc_TELA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.TELA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 69 66 66 75 73 65 64 74 72 61 63 2e 78 79 7a 2f 33 2f 62 62 63 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 77 43 6d 66 6d 52 65 5c 64 74 77 7a 72 51 66 5c 47 5a 54 4a 6f 78 78 2e 65 78 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}