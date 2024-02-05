
rule TrojanDownloader_O97M_EncDoc_J_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.J!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 72 6e 63 77 6e 65 72 5c 43 6b 75 69 51 68 54 58 78 2e 64 6c 6c } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 30 62 2e 68 74 62 2f 73 2e 64 6c 6c } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}