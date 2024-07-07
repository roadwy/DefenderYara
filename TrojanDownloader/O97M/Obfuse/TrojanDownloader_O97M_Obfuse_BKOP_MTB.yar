
rule TrojanDownloader_O97M_Obfuse_BKOP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKOP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 } //1 sd = Chr(df - 103)
		$a_01_1 = {2e 52 75 6e 28 6f 77 75 74 74 61 6b 74 2c 20 75 73 65 76 6e 29 } //1 .Run(owuttakt, usevn)
		$a_01_2 = {43 61 6c 6c 20 6b 6a 78 6b 61 63 6b 61 72 2e 64 64 72 68 70 6f 74 74 6c 66 65 70 6d 76 77 7a 6b 77 73 61 } //1 Call kjxkackar.ddrhpottlfepmvwzkwsa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}