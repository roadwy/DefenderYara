
rule TrojanDownloader_O97M_Donoff_EM{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 28 28 90 02 1a 20 2d 20 36 35 20 2b 20 90 02 10 29 20 4d 6f 64 20 32 36 29 20 2b 20 36 35 29 0d 0a 43 61 73 65 20 39 37 20 54 6f 20 31 32 32 90 00 } //1
		$a_03_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 90 02 10 20 90 02 10 28 22 90 01 04 3a 2f 2f 90 00 } //1
		$a_03_2 = {29 2c 20 31 0d 0a 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 10 22 0d 0a 45 78 69 74 20 53 75 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}