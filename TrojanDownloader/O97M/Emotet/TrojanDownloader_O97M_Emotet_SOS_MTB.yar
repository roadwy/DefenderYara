
rule TrojanDownloader_O97M_Emotet_SOS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SOS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6e 65 77 6b 61 6e 6f 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 36 36 72 49 73 72 56 77 6f 50 4b 55 73 6a 63 41 73 2f 22 2c } //01 00 
		$a_01_1 = {3a 2f 2f 6f 63 61 6c 6f 67 75 6c 6c 61 72 69 2e 63 6f 6d 2f 69 6e 63 2f 57 63 6d 38 32 65 6e 72 73 38 2f 22 2c 22 } //01 00 
		$a_01_2 = {3a 2f 2f 6d 79 70 68 61 6d 63 75 61 74 75 69 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 4f 50 56 65 56 53 70 4f 2f 22 2c 22 } //00 00 
	condition:
		any of ($a_*)
 
}