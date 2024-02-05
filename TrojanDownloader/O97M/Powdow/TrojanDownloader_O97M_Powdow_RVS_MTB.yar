
rule TrojanDownloader_O97M_Powdow_RVS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6b 64 77 6b 64 6f 77 6b 64 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 } //01 00 
		$a_01_1 = {6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6f 77 64 70 6f 77 64 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 } //01 00 
		$a_01_2 = {6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}