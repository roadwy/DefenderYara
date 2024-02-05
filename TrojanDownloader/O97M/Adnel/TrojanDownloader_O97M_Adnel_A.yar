
rule TrojanDownloader_O97M_Adnel_A{
	meta:
		description = "TrojanDownloader:O97M/Adnel.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 75 6c 74 5f 5f 31 2e 4f 70 65 6e 20 63 6f 6e 73 74 61 6e 73 5f 52 65 73 75 6c 74 28 } //01 00 
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 63 6f 6e 73 74 61 6e 73 5f 52 65 73 75 6c 74 28 33 29 29 } //01 00 
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 46 72 65 64 64 79 5f 52 65 73 75 6c 74 2c } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}