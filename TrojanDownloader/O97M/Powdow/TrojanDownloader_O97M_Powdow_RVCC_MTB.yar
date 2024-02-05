
rule TrojanDownloader_O97M_Powdow_RVCC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 24 28 78 78 78 78 78 78 61 29 65 6e 64 73 75 62 } //01 00 
		$a_01_1 = {78 78 78 78 78 78 61 3d 31 31 31 2e 31 31 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 2b 31 31 31 2e 31 31 32 2e 74 61 67 2b 31 31 31 2e 31 31 33 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 2e 70 72 69 6e 74 } //01 00 
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //00 00 
	condition:
		any of ($a_*)
 
}