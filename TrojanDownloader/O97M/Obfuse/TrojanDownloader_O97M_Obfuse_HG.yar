
rule TrojanDownloader_O97M_Obfuse_HG{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HG,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 90 02 25 20 2d 20 90 02 03 29 2e 54 65 78 74 29 90 00 } //01 00 
		$a_03_1 = {2e 52 75 6e 21 20 90 02 14 2c 20 30 20 2b 90 00 } //01 00 
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 } //00 00  .Controls
	condition:
		any of ($a_*)
 
}