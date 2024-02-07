
rule TrojanDownloader_O97M_Obfuse_CM_eml{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CM!eml,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 19 2c 20 90 02 14 2c 20 22 22 29 90 00 } //01 00 
		$a_01_1 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  .Item().Document.Application.ShellExecute
		$a_03_2 = {28 56 61 6c 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 42 75 69 6c 64 29 20 41 6e 64 20 90 04 04 05 28 30 2d 39 29 20 3d 20 90 1b 00 20 41 6e 64 20 90 02 0a 29 20 54 68 65 6e 90 00 } //01 00 
		$a_03_3 = {3d 20 49 73 45 6d 70 74 79 28 90 02 1e 29 90 00 } //01 00 
		$a_03_4 = {26 20 22 22 20 26 20 22 22 20 26 20 52 65 70 6c 61 63 65 28 90 02 1a 2c 20 22 90 02 19 22 2c 20 22 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}