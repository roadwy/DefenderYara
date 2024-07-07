
rule TrojanDownloader_O97M_Obfuse_GW{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GW,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 70 6c 69 74 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 90 02 16 29 2e 52 61 6e 67 65 28 90 02 07 29 2e 56 61 6c 75 65 2c 20 43 68 72 28 34 34 29 29 90 00 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 20 90 02 36 28 30 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 90 00 } //1
		$a_01_2 = {3a 20 43 61 6c 6c } //1 : Call
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}