
rule TrojanDownloader_O97M_Donoff_FI{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FI,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 74 6e 28 90 05 05 04 30 2d 39 2e 29 20 (2b|2d) 20 41 74 6e 28 90 05 05 04 30 2d 39 2e 29 } //1
		$a_03_1 = {4c 54 72 69 6d 28 22 [0-20] 22 29 20 2b 20 4c 54 72 69 6d 28 22 [0-20] 22 29 } //1
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 } //1 Application.Run "
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}