
rule TrojanDownloader_O97M_Powdow_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00 
		$a_00_1 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 68 69 64 64 65 6e 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 20 2d 63 } //01 00 
		$a_00_2 = {6e 73 6c 6f 6f 6b 75 70 20 2d 71 3d 74 78 74 20 6c 2e 6e 73 2e 6f 73 74 72 79 6b 65 62 73 2e 70 6c 2e } //01 00 
		$a_00_3 = {6d 61 74 63 68 20 27 40 28 2e 2a 29 40 27 29 7b 49 45 58 20 24 6d 61 74 63 68 65 73 5b 31 5d } //00 00 
	condition:
		any of ($a_*)
 
}