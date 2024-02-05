
rule TrojanDownloader_O97M_PShell_H{
	meta:
		description = "TrojanDownloader:O97M/PShell.H,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 90 02 20 28 22 68 74 74 70 90 02 02 3a 2f 2f 90 02 30 2f 90 02 10 2e 6a 70 67 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 90 02 10 2e 65 78 65 22 29 90 00 } //01 00 
		$a_00_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 28 53 44 45 2c 20 32 29 } //00 00 
	condition:
		any of ($a_*)
 
}