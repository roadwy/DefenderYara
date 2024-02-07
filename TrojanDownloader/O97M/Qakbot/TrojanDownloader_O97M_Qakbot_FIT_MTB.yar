
rule TrojanDownloader_O97M_Qakbot_FIT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.FIT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 37 70 69 6c 6c 61 72 73 2e 69 6e 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://7pillars.in/ds/291120.gif
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 65 79 6c 61 77 2e 72 6f 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://eylaw.ro/ds/291120.gif
		$a_01_2 = {43 3a 5c 67 69 6f 67 74 69 } //00 00  C:\giogti
	condition:
		any of ($a_*)
 
}