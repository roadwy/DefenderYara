
rule TrojanDownloader_O97M_Dotraj_E{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.E,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 10 22 2c 20 90 02 10 28 90 02 10 28 29 20 26 20 22 22 2c 20 90 00 } //01 00 
		$a_02_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 02 10 20 26 20 22 20 22 20 26 20 90 02 10 2c 20 90 02 10 20 2d 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}