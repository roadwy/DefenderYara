
rule TrojanDownloader_O97M_Qakbot_PDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 70 6c 6f 6b 6f 74 6f 2e 63 66 2f 49 42 36 31 52 4f 30 5a 36 43 2f 33 33 2e 70 6e 67 } //01 00 
		$a_01_1 = {3a 2f 2f 33 36 33 35 6f 70 74 69 63 61 6c 2e 67 61 2f 59 46 50 7a 75 4f 6d 72 2f 33 33 2e 70 6e 67 } //01 00 
		$a_01_2 = {3a 2f 2f 6c 65 6f 65 64 65 6c 75 63 63 61 2e 63 6f 6d 2e 62 72 2f 4a 53 48 69 34 31 57 42 66 76 2f 33 33 2e 70 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}