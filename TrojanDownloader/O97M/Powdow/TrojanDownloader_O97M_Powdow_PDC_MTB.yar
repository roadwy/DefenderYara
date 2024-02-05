
rule TrojanDownloader_O97M_Powdow_PDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 2e 4f 70 65 6e 20 43 68 72 28 37 31 29 20 26 20 43 68 72 28 36 39 29 20 26 20 43 68 72 28 38 34 29 2c 20 43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 35 38 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 35 32 29 20 26 20 43 68 72 28 34 38 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 34 39 29 20 26 20 43 68 72 28 34 39 29 20 26 20 43 68 72 28 35 30 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 35 35 29 20 26 20 5f } //01 00 
		$a_01_1 = {43 68 72 28 34 39 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 35 30 29 20 26 20 43 68 72 28 34 38 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 31 31 38 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 31 30 32 29 20 26 20 43 68 72 28 31 31 37 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 31 31 30 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 2c 20 46 61 6c 73 65 } //01 00 
		$a_01_2 = {2e 77 72 69 74 65 20 6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00 
		$a_01_3 = {6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 2e 53 65 6e 64 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 20 28 43 68 72 28 31 30 32 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 35 30 29 20 26 20 43 68 72 28 31 30 38 29 20 26 20 43 68 72 28 35 30 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}