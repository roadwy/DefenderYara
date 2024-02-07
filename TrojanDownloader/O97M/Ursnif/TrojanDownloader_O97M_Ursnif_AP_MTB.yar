
rule TrojanDownloader_O97M_Ursnif_AP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 33 20 2b 20 32 20 2b 20 35 30 20 2b 20 34 39 20 2b 20 31 29 20 2b 20 22 68 65 6c 6c 22 } //01 00  = Chr(13 + 2 + 50 + 49 + 1) + "hell"
		$a_03_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 4c 65 6e 28 22 90 02 02 22 29 29 2e 56 61 6c 75 65 90 00 } //01 00 
		$a_03_2 = {4f 70 65 6e 20 54 72 69 6d 28 90 02 50 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 90 01 01 2c 20 54 72 69 6d 28 90 00 } //01 00 
		$a_01_4 = {2e 54 65 78 74 } //01 00  .Text
		$a_01_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}