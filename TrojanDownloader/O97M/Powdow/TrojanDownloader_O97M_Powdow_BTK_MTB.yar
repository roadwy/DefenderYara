
rule TrojanDownloader_O97M_Powdow_BTK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 66 69 72 73 74 64 65 67 72 65 65 2e 62 61 74 22 } //1 = "C:\Users\Public\Documents\firstdegree.bat"
		$a_01_1 = {74 72 65 65 61 6c 6f 6e 67 20 26 20 62 72 65 61 6b 6d 6f 72 6e 69 6e 67 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 } //1 treealong & breakmorning & " -w h Start-BitsTransfer -Source htt
		$a_01_2 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 65 61 74 61 6e 64 2e 65 60 78 65 } //1 Destination C:\Users\Public\Documents\eatand.e`xe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}