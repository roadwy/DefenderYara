
rule TrojanDownloader_O97M_Powdow_RVU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 70 6f 77 5e 65 72 73 22 0d 0a [0-14] 3d 20 22 68 65 5e 6c 6c 22 } //1
		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 43 68 72 28 31 31 30 29 20 26 20 22 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 22 20 26 20 43 49 6e 74 28 30 2e 33 29 29 2e 4f 70 65 6e 20 28 [0-0f] 29 } //1
		$a_03_2 = {2d 53 6f 75 72 63 65 20 68 74 74 [0-37] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 65 60 78 65 } //1
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 67 6f 64 2e 62 61 74 } //1 C:\Users\Public\Documents\god.bat
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}