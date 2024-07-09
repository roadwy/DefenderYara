
rule TrojanDownloader_O97M_Donoff_RX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 74 35 20 3d 20 6a 35 20 2b 20 6a 39 39 20 2b 20 72 34 20 2b 20 72 33 33 20 2b 20 72 6d 37 20 2b 20 77 37 20 2b 20 72 39 30 20 2b 20 72 6d 37 20 2b 20 78 34 20 2b 20 79 38 38 20 2b 20 71 31 20 2b 20 78 34 20 2b 20 72 38 39 20 2b 20 78 34 20 2b 20 72 34 } //1 ft5 = j5 + j99 + r4 + r33 + rm7 + w7 + r90 + rm7 + x4 + y88 + q1 + x4 + r89 + x4 + r4
		$a_03_1 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 28 [0-05] 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}