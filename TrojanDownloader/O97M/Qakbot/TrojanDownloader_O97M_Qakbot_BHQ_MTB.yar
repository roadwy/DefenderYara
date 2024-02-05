
rule TrojanDownloader_O97M_Qakbot_BHQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BHQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 73 75 70 65 72 62 69 6b 65 7a 2e 6e 6c 2f 64 30 54 4a 73 47 73 4a 77 2f 67 68 6e 2e 70 6e 67 90 02 0a 43 3a 5c 41 6f 74 5c 90 02 06 2e 6f 63 78 90 00 } //01 00 
		$a_03_1 = {3a 2f 2f 6b 65 72 72 76 69 6c 6c 65 74 75 65 73 64 61 79 74 65 6e 6e 69 73 2e 63 6f 6d 2f 53 7a 41 75 4f 63 54 37 63 39 58 2f 67 68 6e 2e 70 6e 67 90 02 0a 43 3a 5c 41 6f 74 5c 90 02 06 2e 6f 63 78 90 00 } //01 00 
		$a_03_2 = {3a 2f 2f 65 74 68 6e 69 63 63 72 61 66 74 61 72 74 2e 63 6f 6d 2f 4b 73 44 48 43 51 6a 6f 34 38 2f 67 68 6e 2e 70 6e 67 90 02 0a 43 3a 5c 41 6f 74 5c 90 02 06 2e 6f 63 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}