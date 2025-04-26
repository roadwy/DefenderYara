
rule TrojanDownloader_O97M_Powdow_BTIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BTIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 67 6f 64 2e 62 61 74 } //1 = "C:\Users\Public\Documents\god.bat
		$a_03_1 = {2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 5e 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 31 38 2e 31 35 36 2e 37 31 2e 32 33 37 2f 68 4e 2f 35 2f 42 2f [0-30] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-30] 2e 65 60 78 65 } //1
		$a_01_2 = {3d 20 22 70 6f 77 5e 65 72 73 } //1 = "pow^ers
		$a_01_3 = {3d 20 22 68 65 5e 6c 6c } //1 = "he^ll
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}