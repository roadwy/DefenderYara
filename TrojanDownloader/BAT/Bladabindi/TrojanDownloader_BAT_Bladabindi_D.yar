
rule TrojanDownloader_BAT_Bladabindi_D{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 4d 72 2e 5a 61 6d 69 6c 5c 5a 61 6d 69 6c 5c 6f 62 6a 5c 44 65 62 75 67 5c } //01 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 } //01 00 
		$a_01_2 = {3c 4d 6f 64 75 6c 65 3e 00 50 61 74 63 68 2e 65 78 65 00 } //00 00 
		$a_00_3 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}