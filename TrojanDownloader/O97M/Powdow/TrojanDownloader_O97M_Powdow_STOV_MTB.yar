
rule TrojanDownloader_O97M_Powdow_STOV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STOV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 5f 52 75 6e 44 4c 4c 20 22 22 6d 73 68 74 61 22 22 20 22 22 68 74 74 70 3a 2f 2f 77 77 77 2e 61 73 69 61 6e 65 78 70 6f 72 74 67 6c 61 73 73 2e 73 68 6f 70 2f 70 2f 33 2e 68 74 6d 6c 22 22 22 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 21 28 22 72 75 6e 64 6c 6c 33 32 20 22 20 2b 20 6b 75 6c 61 62 65 61 72 29 } //01 00 
		$a_01_2 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 42 65 66 6f 72 65 43 6c 6f 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}