
rule TrojanDownloader_O97M_Qakbot_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 72 65 6e 77 69 6e 61 75 74 6f 76 61 6c 75 65 72 73 2e 63 6f 6d 2f 6a 51 74 69 35 68 6a 56 53 2f 50 6f 6d 4b 2e 70 6e 67 22 2c } //01 00 
		$a_01_1 = {3a 2f 2f 62 75 79 2d 31 30 30 6d 67 76 69 61 67 72 61 2e 63 6f 6d 2f 30 63 70 52 49 44 47 64 6b 42 2f 50 6f 6d 4b 2e 70 6e 67 22 2c } //01 00 
		$a_01_2 = {3a 2f 2f 74 69 6d 65 69 6e 69 6e 64 69 61 6e 6f 77 2e 63 6f 6d 2f 32 52 5a 76 58 30 66 4e 33 33 75 2f 50 6f 6d 4b 2e 70 6e 67 22 2c } //00 00 
	condition:
		any of ($a_*)
 
}