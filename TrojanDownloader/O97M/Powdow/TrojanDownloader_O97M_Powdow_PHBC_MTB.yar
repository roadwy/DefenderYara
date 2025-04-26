
rule TrojanDownloader_O97M_Powdow_PHBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PHBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 60 70 3a 2f 2f 67 72 65 65 6e 70 61 79 69 6e 64 69 61 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 72 6e 74 2f 43 6f 6e 73 6f 6c 65 41 70 70 31 38 2e 65 60 78 65 } //1 htt`p://greenpayindia.com/wp-conternt/ConsoleApp18.e`xe
		$a_03_1 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-14] 2e 65 60 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}