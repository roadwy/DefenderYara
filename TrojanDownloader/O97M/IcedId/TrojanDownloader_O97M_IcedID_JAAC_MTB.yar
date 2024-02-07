
rule TrojanDownloader_O97M_IcedID_JAAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.JAAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 62 79 74 65 73 49 6e 64 65 78 28 6c 6f 6e 67 52 69 67 68 74 2c 20 4f 70 74 69 6f 6e 61 6c 20 77 69 6e 49 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 6c 6f 63 61 6c 43 6e 74 57 20 3d 20 22 61 22 29 } //01 00  Function bytesIndex(longRight, Optional winI = "c:\program", Optional localCntW = "a")
		$a_03_1 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 62 79 74 65 73 49 6e 64 65 78 28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 2c 20 54 72 75 65 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_2 = {26 20 77 69 6e 49 20 26 20 22 64 61 74 61 5c 90 02 20 2e 68 74 22 20 26 20 6c 6f 63 61 6c 43 6e 74 57 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 31 2c 20 90 02 20 43 6c 6f 73 65 20 23 31 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_03_4 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}