
rule TrojanDownloader_O97M_Zloader_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Zloader.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 74 70 3a 2f 2f 61 71 76 2e 74 6f 2f 31 32 2e 6d 73 69 } //01 00 
		$a_00_1 = {50 72 6f 67 72 61 6d 57 36 34 33 32 3a 7e 31 35 25 69 65 78 65 63 2e 65 78 65 } //01 00 
		$a_00_2 = {70 6f 77 65 72 73 68 65 6c } //01 00 
		$a_00_3 = {63 6d 64 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}