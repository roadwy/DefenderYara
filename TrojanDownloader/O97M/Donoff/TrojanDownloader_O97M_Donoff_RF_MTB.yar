
rule TrojanDownloader_O97M_Donoff_RF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 22 20 26 20 22 2e 65 22 20 26 20 22 78 65 20 2f 73 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 90 02 0f 2e 64 6c 6c 22 90 00 } //01 00 
		$a_03_1 = {45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 4c 6f 63 61 6c 20 54 65 6d 70 61 72 79 5c 90 02 0f 2e 65 78 22 20 26 20 22 65 20 43 4f 4d 32 5f 22 90 00 } //01 00 
		$a_01_2 = {20 3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 } //00 00   = CreateProcessA(
		$a_00_3 = {e7 4c } //00 00 
	condition:
		any of ($a_*)
 
}