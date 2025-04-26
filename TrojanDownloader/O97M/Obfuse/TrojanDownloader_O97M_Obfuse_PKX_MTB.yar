
rule TrojanDownloader_O97M_Obfuse_PKX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 61 72 61 6c 61 67 6c 6f 69 72 65 2e 63 6f 6d 2f [0-20] 2f 31 31 2e 70 [0-05] 6e 67 22 2c 22 } //1
		$a_03_1 = {61 62 6e 65 77 73 6c 69 76 65 2e 69 6e 2f [0-20] 2f 31 31 2e 70 6e [0-05] 67 22 2c 22 } //1
		$a_03_2 = {6f 6e 63 65 61 79 65 61 72 70 65 73 74 63 6f 6e 74 72 6f 6c 2e 63 [0-05] 6f 6d 2f [0-20] 2f 31 31 2e 70 [0-05] 6e 67 22 2c 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}