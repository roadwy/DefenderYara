
rule TrojanDownloader_O97M_Emotet_PQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 } //1 = "winmgmts:Wi"
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //1
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 90 02 20 2e 90 00 } //1
		$a_03_3 = {52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 90 02 10 22 2c 20 22 22 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}