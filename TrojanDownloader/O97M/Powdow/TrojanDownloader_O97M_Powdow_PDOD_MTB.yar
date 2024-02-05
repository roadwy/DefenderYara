
rule TrojanDownloader_O97M_Powdow_PDOD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDOD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 6d 6f 6e 65 79 63 6f 75 6e 74 2e 75 78 2b 6d 6f 6e 65 79 63 6f 75 6e 74 2e 74 72 2b 6d 6f 6e 73 74 65 72 63 6f 6d 69 6e 67 2e 7a 2b 6d 6f 6e 73 74 65 72 63 6f 6d 69 6e 67 2e 64 2b 68 69 2e 6f 70 65 6e 6d 61 72 6b 65 74 31 32 34 35 2b 68 69 2e 78 78 78 2b 73 68 6f 77 6f 66 66 2e 6b 6f 6e 73 61 2b 73 68 6f 77 6f 66 66 2e 74 } //01 00 
		$a_01_1 = {6d 73 67 62 6f 78 22 6f 66 66 69 63 65 65 72 72 6f 72 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c 21 28 62 72 6f 6b 65 6e 73 68 6f 77 6f 66 66 29 65 6e 64 73 75 62 } //01 00 
		$a_01_2 = {6d 61 72 6b 65 74 31 32 34 35 3d 74 65 78 74 66 69 6c 65 70 61 72 74 2e 6d 6f 73 75 66 31 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 78 78 78 28 29 61 73 73 74 72 69 6e 67 78 78 78 } //00 00 
	condition:
		any of ($a_*)
 
}