
rule TrojanDownloader_O97M_IcedID_PCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 62 2e 65 78 65 63 28 61 36 39 66 35 63 31 32 29 } //01 00 
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00 
		$a_00_2 = {63 66 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 61 61 37 64 39 33 61 64 } //01 00 
		$a_00_3 = {62 65 61 62 64 32 63 66 2e 53 65 6e 64 } //01 00 
		$a_00_4 = {61 61 20 3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //00 00 
	condition:
		any of ($a_*)
 
}