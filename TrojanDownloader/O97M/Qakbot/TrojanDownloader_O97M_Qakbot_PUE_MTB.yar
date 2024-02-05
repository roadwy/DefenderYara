
rule TrojanDownloader_O97M_Qakbot_PUE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 4a 43 43 43 4a 4a } //01 00 
		$a_00_1 = {4a 4a 43 43 42 42 } //01 00 
		$a_00_2 = {7a 69 70 66 6c 64 72 } //01 00 
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 79 63 31 6f 70 33 6a 68 33 39 72 2e 78 79 7a 2f 67 75 74 70 61 67 2e 70 68 70 } //01 00 
		$a_00_4 = {43 3a 5c 6d 76 6f 72 70 } //01 00 
		$a_00_5 = {5c 6f 6f 6a 66 6a 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}