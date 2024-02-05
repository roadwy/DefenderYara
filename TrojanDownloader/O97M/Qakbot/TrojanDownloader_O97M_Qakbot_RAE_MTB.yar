
rule TrojanDownloader_O97M_Qakbot_RAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 67 6c 72 32 2e 72 65 76 70 64 65 76 2e 63 6f 6d 2f 73 79 61 70 6f 73 6f 74 2f } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}