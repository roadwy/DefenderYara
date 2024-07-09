
rule TrojanDownloader_O97M_FTCdedoc_A_MTB{
	meta:
		description = "TrojanDownloader:O97M/FTCdedoc.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 22 57 53 63 72 69 70 74 2e 22 20 26 20 [0-08] 29 29 2e 52 75 6e 20 [0-08] 2c } //1
		$a_01_1 = {3d 20 22 22 } //1 = ""
		$a_03_2 = {28 22 22 2c 20 43 68 72 28 [0-08] 29 29 } //1
		$a_01_3 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
		$a_01_4 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Private Sub Document_Open()
		$a_01_5 = {22 53 68 65 6c 6c 22 2c } //1 "Shell",
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}