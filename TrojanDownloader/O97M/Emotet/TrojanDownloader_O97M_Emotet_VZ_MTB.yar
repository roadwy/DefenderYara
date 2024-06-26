
rule TrojanDownloader_O97M_Emotet_VZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 20 2b 20 90 02 20 20 2b 20 90 02 20 20 2b 20 90 02 10 2c 20 90 02 20 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 90 01 01 28 22 90 02 35 2c 20 90 02 20 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_2 = {3d 20 49 6e 53 74 72 52 65 76 28 22 90 02 35 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_3 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 90 02 20 20 2b 90 00 } //01 00 
		$a_01_4 = {3d 20 22 22 } //01 00  = ""
		$a_01_5 = {2e 50 61 67 65 73 28 30 29 2e 43 61 70 74 69 6f 6e } //00 00  .Pages(0).Caption
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_VZ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 25 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 25 2e 90 02 30 20 2b 20 90 02 25 20 2b 20 90 02 25 2c 90 00 } //01 00 
		$a_03_1 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 20 2b 20 90 02 20 20 2b 20 90 02 10 2c 20 90 02 20 2c 20 90 02 15 29 90 00 } //01 00 
		$a_03_2 = {2b 20 43 68 72 57 28 90 02 25 2e 5a 6f 6f 6d 90 02 20 29 20 2b 20 22 90 02 40 77 90 02 40 69 90 02 40 6e 90 02 40 33 90 02 40 32 90 02 40 22 20 2b 90 00 } //01 00 
		$a_03_3 = {2b 20 43 68 72 57 28 90 02 25 2e 5a 6f 6f 6d 90 02 20 29 20 2b 20 90 02 20 2e 90 02 20 2e 54 61 67 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}