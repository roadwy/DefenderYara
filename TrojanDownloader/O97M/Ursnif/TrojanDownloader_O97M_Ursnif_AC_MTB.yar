
rule TrojanDownloader_O97M_Ursnif_AC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_01_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 } //01 00 
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 20 2b 20 31 29 } //01 00 
		$a_01_3 = {2e 4f 70 65 6e } //01 00 
		$a_01_4 = {2e 43 6c 6f 73 65 } //01 00 
		$a_01_5 = {2e 56 61 6c 75 65 } //01 00 
		$a_01_6 = {3d 20 43 68 72 28 31 31 35 29 20 2b 20 22 68 22 20 2b 20 22 65 6c 6c 22 } //01 00 
		$a_01_7 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}