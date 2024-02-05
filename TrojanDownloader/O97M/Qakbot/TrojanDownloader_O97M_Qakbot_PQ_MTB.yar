
rule TrojanDownloader_O97M_Qakbot_PQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 52 79 66 20 3d 20 22 45 22 20 26 20 22 22 20 26 20 22 58 22 20 26 20 22 22 20 26 20 22 45 22 20 26 20 22 22 20 26 20 22 43 } //01 00 
		$a_01_1 = {4a 74 72 75 68 72 64 72 67 64 67 20 3d 20 4e 6f 6c 65 72 74 2e 4e 69 6b 61 73 2e 43 61 70 74 69 6f 6e 20 26 20 22 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 } //01 00 
		$a_01_2 = {53 68 65 65 74 73 28 22 42 6f 6f 6c 74 22 29 2e 52 61 6e 67 65 28 22 4b 31 38 22 29 20 3d 20 22 2e 64 22 20 26 20 22 61 22 20 26 20 22 74 } //00 00 
	condition:
		any of ($a_*)
 
}