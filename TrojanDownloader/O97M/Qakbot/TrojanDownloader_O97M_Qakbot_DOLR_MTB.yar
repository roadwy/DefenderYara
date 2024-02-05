
rule TrojanDownloader_O97M_Qakbot_DOLR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 47 31 30 22 29 20 3d 20 22 2e 2e 5c 47 69 43 65 6c 6f 64 2e 77 61 47 69 63 } //01 00 
		$a_01_1 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 47 31 31 22 29 20 3d 20 22 2e 2e 5c 47 69 43 65 6c 6f 64 2e 77 61 47 69 63 22 } //01 00 
		$a_01_2 = {53 68 65 65 74 73 28 22 46 69 6b 6f 70 22 29 2e 52 61 6e 67 65 28 22 47 31 32 22 29 20 3d 20 22 2e 2e 5c 47 69 43 65 6c 6f 64 2e 77 61 47 69 63 22 } //00 00 
	condition:
		any of ($a_*)
 
}