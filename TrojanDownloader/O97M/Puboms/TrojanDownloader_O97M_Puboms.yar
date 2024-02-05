
rule TrojanDownloader_O97M_Puboms{
	meta:
		description = "TrojanDownloader:O97M/Puboms,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 28 90 02 10 20 2b 20 22 20 68 74 74 70 3a 2f 2f 6f 63 74 61 70 2e 69 67 67 2e 62 69 7a 2f 31 2f 90 02 10 2e 6d 73 69 22 29 90 00 } //01 00 
		$a_00_1 = {22 6d 73 69 65 78 65 63 20 2f 71 20 2f 69 22 } //00 00 
	condition:
		any of ($a_*)
 
}