
rule TrojanDownloader_O97M_Donoff_A{
	meta:
		description = "TrojanDownloader:O97M/Donoff.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 90 0e 04 00 23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 90 0e 04 00 90 12 14 00 90 0e 04 00 23 45 6c 73 65 49 66 20 57 69 6e 33 32 20 54 68 65 6e 90 0e 04 00 90 12 14 00 20 3d 20 22 90 12 14 00 22 90 0e 04 00 90 12 14 00 20 3d 20 22 } //1
		$a_03_1 = {23 45 6c 73 65 90 0e 04 00 23 45 6e 64 20 49 66 90 0e 04 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}