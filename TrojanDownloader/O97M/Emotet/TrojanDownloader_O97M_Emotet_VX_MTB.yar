
rule TrojanDownloader_O97M_Emotet_VX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-20] 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-10] 2c 20 [0-20] 2c 20 [0-20] 29 } //1
		$a_03_1 = {29 20 2b 20 [0-30] 77 [0-30] 69 [0-30] 6e [0-30] 33 [0-30] 32 [0-30] 5f [0-30] 22 20 2b 20 [0-20] 2e [0-40] 72 [0-30] 6f [0-30] 63 [0-30] 65 [0-30] 73 [0-30] 73 [0-30] 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}