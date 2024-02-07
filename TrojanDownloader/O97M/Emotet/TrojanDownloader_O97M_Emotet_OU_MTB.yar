
rule TrojanDownloader_O97M_Emotet_OU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 57 69 6e 90 02 20 33 90 02 20 32 90 02 20 5f 90 02 20 50 90 02 20 72 90 02 20 6f 90 02 20 63 90 02 20 65 90 02 20 73 90 02 20 73 90 02 20 22 2c 20 90 02 15 2c 20 90 02 10 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 15 2c 20 90 02 15 2c 20 90 02 15 2c 20 90 02 15 29 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 45 2c 20 90 02 45 2c 20 22 22 29 90 00 } //01 00 
		$a_01_3 = {30 2c 20 30 2c 20 4d 53 46 6f 72 6d 73 2c 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 22 } //00 00  0, 0, MSForms, CommandButton"
	condition:
		any of ($a_*)
 
}