
rule TrojanDownloader_O97M_Obfusmacro_AA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfusmacro.AA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 96 2b 20 22 90 02 2f 77 90 02 08 69 90 02 08 6e 90 02 08 6d 67 90 02 08 6d 90 02 08 74 73 90 02 08 3a 90 02 0f 57 90 02 08 69 90 02 08 6e 90 02 0f 5f 90 02 08 50 90 02 08 72 90 02 08 6f 90 02 08 63 90 02 08 65 90 02 08 73 73 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 38 2c 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 35 2c 90 00 } //01 00 
		$a_01_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00  Sub autoopen()
		$a_01_4 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 } //00 00  , MSForms, TextBox"
		$a_00_5 = {5d 04 00 00 98 f7 03 80 5c 33 00 00 99 } //f7 03 
	condition:
		any of ($a_*)
 
}