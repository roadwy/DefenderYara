
rule TrojanDownloader_O97M_Valak_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 5f 6f 35 20 3d 20 22 68 74 74 70 73 3a 2f 2f 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 25 36 39 40 6a 2e 6d 70 } //01 00 
		$a_00_1 = {76 62 5f 6e 61 6d 65 3d 22 7a 75 62 62 69 5f } //01 00 
		$a_00_2 = {4c 5f 6f 31 20 3d 20 22 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}