
rule TrojanDownloader_O97M_Qakbot_DOLZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 69 43 65 6c 6f 64 2e 77 61 47 69 63 } //01 00 
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 48 33 22 29 } //01 00 
		$a_01_2 = {2e 49 6e 74 65 72 69 6f 72 2e 43 6f 6c 6f 72 20 3d 20 76 62 42 6c 61 63 6b } //01 00 
		$a_01_3 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 44 65 6c 65 74 65 } //01 00 
		$a_01_4 = {53 65 74 20 46 65 72 61 20 3d 20 45 78 63 65 6c 34 49 6e 74 6c 4d 61 63 72 6f 53 68 65 65 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}