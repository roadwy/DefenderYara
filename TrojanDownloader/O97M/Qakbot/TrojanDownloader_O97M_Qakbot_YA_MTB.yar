
rule TrojanDownloader_O97M_Qakbot_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 65 72 74 69 6c 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 49 55 54 46 75 79 } //01 00 
		$a_01_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 4a 65 72 69 6e 54 72 61 22 29 } //01 00 
		$a_01_2 = {52 65 64 65 72 65 73 74 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 54 72 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}