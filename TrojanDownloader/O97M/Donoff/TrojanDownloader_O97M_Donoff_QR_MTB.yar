
rule TrojanDownloader_O97M_Donoff_QR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {28 22 2f 70 68 2f 3a 74 74 22 29 } //1 ("/ph/:tt")
		$a_01_1 = {28 22 70 2f 3a 2f 74 68 74 22 29 } //1 ("p/:/tht")
		$a_01_2 = {70 65 72 66 6f 72 6d 57 72 69 74 65 } //1 performWrite
		$a_01_3 = {28 22 33 20 75 32 64 6e 72 6c 6c 22 29 } //1 ("3 u2dnrll")
		$a_01_4 = {28 22 64 20 6c 6c 32 72 75 33 6e 22 29 } //1 ("d ll2ru3n")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}