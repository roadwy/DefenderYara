
rule TrojanDownloader_O97M_Ursnif_AH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 5c 90 02 10 2e 22 20 26 90 00 } //1
		$a_01_1 = {3d 20 22 74 65 6d 70 22 } //1 = "temp"
		$a_01_2 = {3d 20 22 65 78 65 22 } //1 = "exe"
		$a_01_3 = {50 75 74 20 23 6e 46 69 6c 65 4e 75 6d 2c 20 2c 20 43 42 79 74 65 28 22 26 48 22 20 26 20 61 72 72 42 79 74 65 73 28 69 29 29 } //1 Put #nFileNum, , CByte("&H" & arrBytes(i))
		$a_03_4 = {2e 73 31 2e 56 61 6c 75 65 20 26 20 90 02 10 2e 73 32 2e 54 65 78 74 90 00 } //1
		$a_01_5 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_03_6 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 10 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}