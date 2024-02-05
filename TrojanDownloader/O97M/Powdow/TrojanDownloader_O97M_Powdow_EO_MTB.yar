
rule TrojanDownloader_O97M_Powdow_EO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 61 64 64 6c 65 64 73 74 65 61 6d 62 2e 78 79 7a 2f 42 41 59 67 4f 44 41 30 4e 55 51 32 4f 45 59 31 52 54 41 32 4f 44 67 34 52 44 68 43 51 7a 6c 45 51 7a 52 42 52 55 55 33 51 54 41 35 4f 55 49 3d } //01 00 
		$a_01_1 = {43 3a 5c 54 51 4b 63 5a 77 53 5c 71 77 73 46 49 57 72 5c 74 44 4e 49 6c 42 54 2e 64 6c 6c } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}