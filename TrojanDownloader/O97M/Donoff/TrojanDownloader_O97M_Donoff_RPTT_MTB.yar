
rule TrojanDownloader_O97M_Donoff_RPTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RPTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {67 65 74 6f 62 6a 65 63 74 28 22 [0-5f] 22 29 2e 65 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 28 22 7b [0-5f] 7d 22 29 3d 22 68 74 74 70 3a 2f 2f 70 72 6f 74 6f 6e 6f 73 6b 6f 2e 68 6f 73 74 2f 78 73 2f 72 6f 76 6a 6d 6d 77 38 65 74 74 70 75 68 66 78 68 72 32 30 33 63 76 77 6d 6e 6e 67 75 79 6b 38 67 71 7e 7e 2f 64 61 74 66 70 68 7a 6b 74 6c 71 73 6b 70 62 6f 31 66 70 74 70 32 62 62 34 36 39 6b 74 6e 70 69 78 61 7e 7e 2f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}