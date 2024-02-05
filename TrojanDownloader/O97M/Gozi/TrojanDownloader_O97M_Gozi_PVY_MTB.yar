
rule TrojanDownloader_O97M_Gozi_PVY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.PVY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6f 6e 6c 69 6e 65 2d 64 6f 63 75 2d 73 69 67 6e 2d 73 74 2e 63 6f 6d 2f 79 79 74 72 2e 70 6e 67 } //01 00 
		$a_00_1 = {43 3a 5c 66 79 6a 68 } //00 00 
	condition:
		any of ($a_*)
 
}