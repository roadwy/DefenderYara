
rule TrojanDownloader_O97M_Blokyst_A{
	meta:
		description = "TrojanDownloader:O97M/Blokyst.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 5c 41 70 22 20 2b 20 22 70 44 61 22 20 2b 20 22 74 61 5c 52 6f 61 22 20 2b 20 22 6d 69 6e 67 22 20 26 20 22 5c 22 } //01 00 
		$a_00_1 = {27 25 41 50 50 44 41 54 41 25 5c 66 6f 27 20 2b 20 27 6c 64 31 27 20 2b 20 27 5c 70 72 69 27 20 2b 20 27 6e 74 65 72 2e 65 27 20 2b 20 27 78 65 27 29 } //00 00 
	condition:
		any of ($a_*)
 
}