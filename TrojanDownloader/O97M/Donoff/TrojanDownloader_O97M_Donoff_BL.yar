
rule TrojanDownloader_O97M_Donoff_BL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BL,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 4f 4c 77 38 6f 4f 77 43 55 6f 35 6b 2c 20 49 71 6e 54 66 30 6d 33 72 34 56 6b 56 2c 20 34 2c 20 57 34 4b 66 65 74 74 41 32 59 7a } //2 CallByName OLw8oOwCUo5k, IqnTf0m3r4VkV, 4, W4KfettA2Yz
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_O97M_Donoff_BL_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BL,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {71 4d 33 6d 78 32 6e 3a 90 0c 03 00 61 38 6c 6d 68 44 50 62 45 6c 7a 76 20 3d 20 28 6e 4e 66 4a 39 71 42 41 44 69 47 50 5a 68 20 2d 20 64 77 77 47 51 70 41 31 4a 36 30 76 4e 4b 45 29 20 2f 20 90 1d 10 00 2e 78 77 69 4a 54 4d 42 42 69 57 37 4d 28 57 78 63 56 4f 50 65 52 47 69 72 41 50 41 29 } //1
		$a_02_1 = {46 6f 72 20 72 37 37 6c 49 67 4c 63 43 38 42 49 54 53 35 20 3d 20 31 20 54 6f 20 61 38 6c 6d 68 44 50 62 45 6c 7a 76 90 0c 03 00 6a 73 65 41 44 51 7a 4a 43 6a 63 69 53 20 3d 20 90 1d 10 00 2e 75 56 62 50 56 72 51 28 57 78 63 56 4f 50 65 52 47 69 72 41 50 41 2c 20 72 37 37 6c 49 67 4c 63 43 38 42 49 54 53 35 29 20 26 20 6a 73 65 41 44 51 7a 4a 43 6a 63 69 53 } //1
		$a_00_2 = {6a 39 4c 31 72 7a 7a 4c 44 54 4d 56 20 3d 20 59 78 49 68 50 6f 46 47 30 76 4a 71 76 63 39 20 2d 20 28 28 59 78 49 68 50 6f 46 47 30 76 4a 71 76 63 39 20 5c 20 4c 30 4b 75 4f 54 29 20 2a 20 4c 30 4b 75 4f 54 29 } //1 j9L1rzzLDTMV = YxIhPoFG0vJqvc9 - ((YxIhPoFG0vJqvc9 \ L0KuOT) * L0KuOT)
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}