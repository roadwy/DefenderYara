
rule TrojanDownloader_O97M_Emotet_AAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 28 29 [0-20] 20 3d 20 43 68 72 28 [0-30] 2e 5a 6f 6f 6d 20 2b 20 [0-04] 20 2b 20 [0-10] 29 } //1
		$a_03_1 = {45 6e 64 20 49 66 [0-20] 20 3d 20 [0-30] 2e [0-20] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1
		$a_03_2 = {3d 20 22 22 [0-10] 20 3d 20 43 68 72 24 28 [0-03] 29 20 26 } //1
		$a_03_3 = {4c 6f 6f 70 90 0c 02 00 45 6e 64 20 49 66 [0-10] 20 3d 20 [0-30] 2e [0-20] 2e 50 61 67 65 73 28 31 29 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1
		$a_03_4 = {26 20 43 68 72 24 28 [0-03] 29 90 0c 02 00 49 66 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}