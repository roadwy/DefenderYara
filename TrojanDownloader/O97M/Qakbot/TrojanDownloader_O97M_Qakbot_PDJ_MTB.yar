
rule TrojanDownloader_O97M_Qakbot_PDJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 66 65 72 61 6f 70 74 69 63 61 6c 2e 63 6f 6d 2f 48 4c 6c 79 4a 35 31 33 7a 75 2f 43 6e 68 66 6e 76 6d 68 2e 70 6e 67 } //01 00 
		$a_01_1 = {64 75 64 64 61 73 2e 63 6f 6d 2e 62 72 2f 46 4d 50 68 6d 6b 44 39 67 32 77 5a 2f 43 6e 68 66 6e 76 6d 68 2e 70 6e 67 } //01 00 
		$a_01_2 = {69 72 61 71 2d 6d 61 73 2e 63 6f 6d 2f 71 4a 39 79 50 63 58 33 64 6e 2f 43 6e 68 66 6e 76 6d 68 2e 70 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}