
rule TrojanDownloader_O97M_Powdow_OISM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.OISM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 35 2e 31 34 37 2e 32 33 30 2e 32 34 38 2f 6f 77 65 72 73 69 74 65 2e 65 78 65 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 72 61 74 63 6f 64 65 2e 65 78 65 22 2c 20 31 29 } //00 00 
	condition:
		any of ($a_*)
 
}