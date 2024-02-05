
rule TrojanDownloader_O97M_Powdow_PRB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PRB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 22 20 26 20 22 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 30 2e 30 2e 30 2e 31 33 2f 70 61 79 6c 6f 61 64 2e 74 78 74 27 29 29 22 } //00 00 
	condition:
		any of ($a_*)
 
}