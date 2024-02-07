
rule TrojanDownloader_O97M_Obfuse_JAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 74 72 43 6f 6e 76 28 90 02 08 2c 20 76 62 55 6e 69 63 6f 64 65 29 90 00 } //01 00 
		$a_03_1 = {4d 69 64 28 90 02 08 2c 20 90 02 0f 2c 20 31 29 90 00 } //01 00 
		$a_03_2 = {2e 65 78 65 63 28 90 02 08 29 90 00 } //01 00 
		$a_03_3 = {53 70 6c 69 74 28 90 02 08 2c 20 90 02 08 29 90 00 } //01 00 
		$a_01_4 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 } //00 00  As String = "scripting.file
	condition:
		any of ($a_*)
 
}