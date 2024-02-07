
rule TrojanDownloader_O97M_Ursnif_AT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 31 35 20 2b 20 30 29 20 2b 20 22 48 45 4c 4c 2e 22 } //01 00  = Chr(115 + 0) + "HELL."
		$a_03_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 90 02 55 29 2e 56 61 6c 75 65 90 00 } //01 00 
		$a_03_2 = {4f 70 65 6e 20 54 72 69 6d 28 90 02 55 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 90 01 01 2c 20 54 72 69 6d 28 90 00 } //01 00 
		$a_01_4 = {43 6c 6f 73 65 20 23 } //00 00  Close #
	condition:
		any of ($a_*)
 
}