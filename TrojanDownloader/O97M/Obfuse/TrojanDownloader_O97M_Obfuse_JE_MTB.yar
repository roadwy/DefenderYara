
rule TrojanDownloader_O97M_Obfuse_JE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f 67 6f 76 65 72 6e 6f 73 70 2e 63 6f 6d 2e 62 72 2f 90 02 0a 2e 68 74 61 90 00 } //01 00 
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //00 00  Public Sub Auto_Open()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } //01 00  , Null, Null, Null
		$a_03_1 = {29 20 26 20 22 23 22 90 02 02 4e 65 78 74 90 00 } //01 00 
		$a_03_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 40 29 20 53 74 65 70 20 32 90 02 02 4d 69 64 28 90 00 } //01 00 
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 40 2c 20 22 23 22 2c 20 22 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}