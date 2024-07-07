
rule TrojanDownloader_O97M_Obfuse_DM{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 7a 28 29 } //1 Public Sub z()
		$a_03_1 = {3d 20 56 42 41 2e 53 68 65 6c 6c 28 90 02 10 2c 20 30 29 90 00 } //1
		$a_03_2 = {3d 20 53 67 6e 28 90 02 08 2e 90 02 10 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}