
rule TrojanDownloader_O97M_FTCdedoc_C_MTB{
	meta:
		description = "TrojanDownloader:O97M/FTCdedoc.C!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 [0-15] 29 2e 52 75 6e 20 [0-15] 2c } //1
		$a_03_1 = {26 20 22 2e 22 20 26 20 28 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 [0-08] 22 2c 20 22 22 29 29 } //1
		$a_01_2 = {3d 20 22 22 } //1 = ""
		$a_03_3 = {28 22 22 2c 20 43 68 72 28 [0-15] 29 29 } //1
		$a_01_4 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
		$a_01_5 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Private Sub Document_Open()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}