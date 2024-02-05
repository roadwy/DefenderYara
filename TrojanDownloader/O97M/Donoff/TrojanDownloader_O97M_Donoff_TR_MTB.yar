
rule TrojanDownloader_O97M_Donoff_TR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.TR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 20 22 74 22 2c 20 22 63 6d 64 20 2f 73 20 2f 6b 20 22 } //01 00 
		$a_01_1 = {22 2e 68 22 20 26 20 62 72 46 6f 72 50 72 6f 63 20 26 20 22 61 22 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 28 66 75 6e 63 46 6f 72 2c 20 22 6b 6b 6c 6b 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 69 44 65 66 69 6e 65 48 74 6d 6c 20 26 20 62 72 46 6f 72 50 72 6f 63 29 } //00 00 
	condition:
		any of ($a_*)
 
}