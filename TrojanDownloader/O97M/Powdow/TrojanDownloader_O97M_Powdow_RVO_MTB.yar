
rule TrojanDownloader_O97M_Powdow_RVO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 74 72 52 65 76 65 72 73 65 28 22 90 02 14 2f 6d 6f 63 2e 79 6c 74 69 62 2e 77 77 77 2f 2f 3a 73 70 74 74 68 22 29 29 90 00 } //01 00 
		$a_01_1 = {63 6f 6d 61 6e 6e 6f 20 3d 20 28 56 42 41 2e 53 74 72 52 65 76 65 72 73 65 28 22 61 74 68 73 6d 22 29 29 } //01 00  comanno = (VBA.StrReverse("athsm"))
		$a_01_2 = {56 42 41 20 5f 0d 0a 2e 20 5f 0d 0a 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 23 20 62 69 69 6c 6c 69 20 5f 0d 0a 2e 20 5f 0d 0a 63 6f 6d 61 6e 6e 6f 20 5f 0d 0a 2c 20 62 61 62 61 62 61 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}