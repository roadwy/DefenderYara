
rule TrojanDownloader_O97M_Qakbot_GDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.GDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 61 72 61 76 65 6c 2e 67 61 6c 6c 61 6d 6f 64 61 2e 63 6f 6d 2f 64 65 66 6c 67 72 71 61 6e 71 6d 76 2f } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00 
		$a_01_2 = {43 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}