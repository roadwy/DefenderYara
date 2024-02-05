
rule TrojanDownloader_O97M_Powdow_SPKW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SPKW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 67 6e 69 77 2f 6d 6f 63 2e 61 6e 61 68 67 65 69 73 73 75 61 2f 2f 3a 70 74 74 68 } //00 00 
	condition:
		any of ($a_*)
 
}