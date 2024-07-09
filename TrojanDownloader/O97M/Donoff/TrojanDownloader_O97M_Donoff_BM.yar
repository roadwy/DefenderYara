
rule TrojanDownloader_O97M_Donoff_BM{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {28 29 20 41 73 20 4f 62 6a 65 63 74 0d 0a 44 69 } //1
		$a_00_1 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 0d 0a } //1
		$a_00_2 = {3d 20 22 22 20 26 20 } //1 = "" & 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_BM_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {4d 4a 67 76 68 6f 3a 90 0c 03 00 7a 4d 70 64 53 45 32 56 45 56 57 58 66 20 3d 20 28 50 36 74 77 65 72 77 6f 20 2d 20 51 31 77 78 75 34 72 31 43 66 42 29 20 2f 20 90 1d 10 00 2e 6b 68 54 57 68 4a 63 63 6d 68 69 69 68 28 67 49 37 4d 45 63 6d 29 } //1
		$a_00_1 = {48 35 5a 66 4c 45 51 64 38 53 20 3d 20 58 52 5a 62 41 36 28 4d 4b 42 45 71 33 2c 20 28 64 62 76 7a 76 46 4b 79 20 2a 20 51 31 77 78 75 34 72 31 43 66 42 29 20 2b 20 55 4d 45 44 46 67 74 37 42 69 55 70 51 7a 68 29 } //1 H5ZfLEQd8S = XRZbA6(MKBEq3, (dbvzvFKy * Q1wxu4r1CfB) + UMEDFgt7BiUpQzh)
		$a_00_2 = {72 76 74 75 44 42 74 35 20 3d 20 4f 59 61 50 79 47 74 44 4b 6d 65 78 73 57 6d 20 2d 20 28 28 4f 59 61 50 79 47 74 44 4b 6d 65 78 73 57 6d 20 5c 20 6a 65 45 61 69 36 54 4e 43 5a 6c 77 55 39 29 20 2a 20 6a 65 45 61 69 36 54 4e 43 5a 6c 77 55 39 29 } //1 rvtuDBt5 = OYaPyGtDKmexsWm - ((OYaPyGtDKmexsWm \ jeEai6TNCZlwU9) * jeEai6TNCZlwU9)
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}