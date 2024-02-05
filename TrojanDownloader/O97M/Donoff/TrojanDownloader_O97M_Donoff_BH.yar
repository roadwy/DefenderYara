
rule TrojanDownloader_O97M_Donoff_BH{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BH,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 66 71 52 69 6b 67 2e 64 75 6a 53 47 50 6b 56 65 59 28 22 77 4d 69 59 6e 6f 6d 30 67 47 6d 59 74 64 73 6a 3a 47 6f 48 22 2c 20 31 38 32 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}