
rule TrojanDownloader_O97M_Ursnif_AV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 5c 5c 70 6d 65 74 5c 5c 5c 5c 73 77 6f 64 6e 69 77 5c 5c 5c 5c 3a 63 22 29 } //01 00  = StrReverse("\\\\pmet\\\\swodniw\\\\:c")
		$a_03_1 = {2e 69 6e 66 22 2c 20 90 02 09 2e 76 61 6c 75 65 90 00 } //01 00 
		$a_03_2 = {2e 73 63 74 22 2c 20 90 02 09 2e 76 61 6c 75 65 90 00 } //01 00 
		$a_03_3 = {53 6c 65 65 70 20 90 10 05 00 90 00 } //02 00 
		$a_03_4 = {53 74 72 52 65 76 65 72 73 65 28 22 20 73 2f 20 69 6e 2f 20 70 74 73 6d 63 22 29 20 26 20 90 02 09 20 26 20 22 90 02 0f 2e 69 6e 66 22 90 00 } //00 00 
		$a_00_5 = {8f b8 00 00 07 00 07 00 07 00 00 01 } //00 18 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Ursnif_AV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 31 35 20 2b 20 30 29 20 2b 20 22 48 45 4c 4c 2e 22 } //01 00  = Chr(115 + 0) + "HELL."
		$a_01_1 = {2e 43 6f 6e 74 72 6f 6c 73 } //01 00  .Controls
		$a_03_2 = {2e 56 61 6c 75 65 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_3 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 0c 02 00 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 90 00 } //01 00 
		$a_03_4 = {4f 70 65 6e 20 54 72 69 6d 28 90 02 55 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_5 = {50 72 69 6e 74 20 23 90 01 01 2c 20 54 72 69 6d 28 90 00 } //01 00 
		$a_01_6 = {43 6c 6f 73 65 20 23 } //00 00  Close #
	condition:
		any of ($a_*)
 
}