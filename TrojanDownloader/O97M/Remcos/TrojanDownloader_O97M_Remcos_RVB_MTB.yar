
rule TrojanDownloader_O97M_Remcos_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 41 6c 48 65 70 2e 4f 70 65 6e 20 28 72 4e 4a 6f 7a 20 2b 20 22 5c 61 66 4a 4e 50 2e 6a 73 22 29 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 65 6c 6c 73 28 31 2c 20 31 29 29 } //01 00 
		$a_01_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 4f 4c 45 4f 62 6a 65 63 74 73 28 31 29 2e 43 6f 70 79 } //01 00 
		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 41 63 74 69 76 61 74 65 28 29 0d 0a 43 61 6c 6c 20 67 55 41 71 } //00 00 
	condition:
		any of ($a_*)
 
}