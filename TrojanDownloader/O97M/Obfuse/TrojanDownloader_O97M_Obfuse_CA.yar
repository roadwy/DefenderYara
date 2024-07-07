
rule TrojanDownloader_O97M_Obfuse_CA{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 53 68 61 70 65 73 28 90 02 20 20 2b 20 90 02 20 20 2b 20 90 02 20 29 2e 54 65 78 74 46 72 61 6d 65 90 00 } //1
		$a_03_1 = {3d 20 41 72 72 61 79 28 90 02 10 2c 20 90 02 10 2c 20 90 02 10 2c 20 53 68 65 6c 6c 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}