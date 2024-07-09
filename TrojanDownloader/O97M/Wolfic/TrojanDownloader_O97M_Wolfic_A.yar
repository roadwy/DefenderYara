
rule TrojanDownloader_O97M_Wolfic_A{
	meta:
		description = "TrojanDownloader:O97M/Wolfic.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2e 55 6e 70 72 6f 74 65 63 74 [0-20] 28 22 64 72 61 67 6f 6e 22 29 } //1
		$a_02_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-40] 2e 43 61 70 74 69 6f 6e 20 26 20 [0-40] 2e 43 61 70 74 69 6f 6e 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}