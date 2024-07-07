
rule TrojanDownloader_O97M_FTCdedoc_B_MTB{
	meta:
		description = "TrojanDownloader:O97M/FTCdedoc.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 15 29 2e 52 75 6e 20 90 02 08 2c 90 00 } //1
		$a_01_1 = {63 72 69 70 74 2e 53 68 65 6c 6c 22 } //1 cript.Shell"
		$a_03_2 = {28 22 22 2c 20 43 68 72 28 90 02 08 29 29 90 00 } //1
		$a_01_3 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
		$a_01_4 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Private Sub Document_Open()
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}