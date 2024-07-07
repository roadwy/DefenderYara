
rule TrojanDownloader_O97M_Donoff_ESM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ESM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 22 66 79 66 2f 90 05 04 04 73 6a 66 67 22 29 90 00 } //1
		$a_03_1 = {28 22 66 79 66 2f 90 02 4f 2f 68 6f 6a 6d 73 76 69 2e 74 6b 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}