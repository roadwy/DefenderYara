
rule TrojanDownloader_O97M_Emotet_SAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6f 5d 62 32 5b 73 5d 62 32 5b 73 63 65 5d 62 32 5b 73 73 5d 62 32 5b 73 73 5d 62 32 5b 73 5d 62 32 5b 73 22 } //01 00 
		$a_01_1 = {3a 77 5d 62 32 5b 73 5d 62 32 5b 73 69 6e 5d 62 32 5b 73 33 5d 62 32 5b 73 32 5d 62 32 5b 73 5f 5d 62 32 5b 73 22 } //01 00 
		$a_01_2 = {77 5d 62 32 5b 73 69 6e 5d 62 32 5b 73 6d 5d 62 32 5b 73 67 6d 5d 62 32 5b 73 74 5d 62 32 5b 73 5d 62 32 5b 73 22 } //01 00 
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 5d 62 32 5b 73 22 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_4 = {2e 43 72 65 61 74 65 20 90 02 20 28 90 02 20 29 2c 20 90 02 20 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}