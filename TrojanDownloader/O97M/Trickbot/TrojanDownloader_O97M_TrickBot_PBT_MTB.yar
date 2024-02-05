
rule TrojanDownloader_O97M_TrickBot_PBT_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.PBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 22 63 3a 5c 2e 2e 5c 73 79 73 6c 6f 67 73 } //01 00 
		$a_00_1 = {6e 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 73 79 73 6c 6f 67 73 5c 66 61 2e 76 62 73 22 29 } //01 00 
		$a_00_2 = {52 65 74 50 69 64 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 46 69 65 6c 64 57 6f 72 64 31 29 } //01 00 
		$a_00_3 = {52 65 74 50 69 64 2e 63 72 65 61 74 65 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 7a 69 70 66 6c 64 72 2e 64 6c 6c 2c } //01 00 
		$a_00_4 = {52 6f 75 74 65 54 68 65 43 61 6c 6c 20 63 3a 5c 73 79 73 6c 6f 67 73 5c 66 61 2e 76 62 73 22 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 30 20 2b 20 30 } //00 00 
	condition:
		any of ($a_*)
 
}