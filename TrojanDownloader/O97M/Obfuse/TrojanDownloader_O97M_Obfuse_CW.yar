
rule TrojanDownloader_O97M_Obfuse_CW{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CW,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00  Sub autoopen()
		$a_02_1 = {53 68 65 6c 6c 20 90 02 70 2c 20 90 00 } //01 00 
		$a_02_2 = {43 68 72 28 4b 65 79 43 6f 64 65 43 6f 6e 73 74 61 6e 74 73 2e 76 62 4b 65 79 50 29 20 2b 20 90 02 70 2c 20 90 10 07 00 20 2d 20 90 10 07 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}