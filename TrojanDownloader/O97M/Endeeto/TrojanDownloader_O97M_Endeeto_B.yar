
rule TrojanDownloader_O97M_Endeeto_B{
	meta:
		description = "TrojanDownloader:O97M/Endeeto.B,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 } //01 00  = CreateObject("MSXML2.XMLHTTP")
		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //01 00  .Open "GET",
		$a_01_2 = {50 75 62 6c 69 63 20 53 75 62 20 57 50 41 4d 48 4f 28 29 0d 0a 20 20 20 20 44 6f 77 6e 6c 6f 61 64 5f 46 69 6c 65 } //01 00 
		$a_01_3 = {2e 72 65 61 64 79 53 74 61 74 65 20 3c 3e 20 34 0d 0a 20 20 20 20 44 6f 45 76 65 6e 74 73 0d 0a 20 20 20 20 4c 6f 6f 70 } //01 00 
		$a_01_4 = {45 6e 76 69 72 6f 6e 28 22 48 4f 4d 45 50 41 54 48 22 29 } //00 00  Environ("HOMEPATH")
	condition:
		any of ($a_*)
 
}