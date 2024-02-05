
rule TrojanDownloader_O97M_Dotraj_M{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.M,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 65 74 4f 62 6a 65 63 74 28 90 01 16 90 02 40 29 2e 43 72 65 61 74 65 90 04 ff 0e 28 29 61 2d 7a 30 2d 39 20 2b 0d 0a 5f 2e 90 05 ff 0e 28 29 61 2d 7a 30 2d 39 20 2b 0d 0a 5f 2e 2c 20 90 05 20 08 61 2d 7a 30 2d 39 5f 2e 2c 20 90 05 20 08 61 2d 7a 30 2d 39 5f 2e 2c 20 90 05 30 08 61 2d 7a 30 2d 39 5f 2e 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}