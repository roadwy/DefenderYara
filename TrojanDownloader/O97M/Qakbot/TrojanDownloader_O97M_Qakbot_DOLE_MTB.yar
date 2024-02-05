
rule TrojanDownloader_O97M_Qakbot_DOLE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 22 20 26 20 22 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 } //01 00 
		$a_01_1 = {3d 20 22 42 79 75 6b 69 6c 6f 73 } //01 00 
		$a_01_2 = {3d 20 22 2e 64 22 20 26 20 22 61 22 20 26 20 22 74 } //01 00 
		$a_01_3 = {49 39 2c 49 31 30 26 4a 31 30 2c 49 31 31 2c 49 31 32 2c 2c 31 2c 39 } //00 00 
	condition:
		any of ($a_*)
 
}