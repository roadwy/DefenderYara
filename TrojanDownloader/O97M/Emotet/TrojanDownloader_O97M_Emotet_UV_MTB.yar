
rule TrojanDownloader_O97M_Emotet_UV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_01_2 = {3d 20 43 68 72 57 28 6f 77 64 73 64 20 2b 20 77 64 4b 65 79 50 20 2b 20 6b 77 6d } //01 00 
		$a_01_3 = {53 48 6f 57 77 69 4e 44 6f 77 21 20 3d 20 46 61 6c 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}