
rule TrojanDownloader_BAT_Bladabindi_E{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 4a 53 65 72 76 65 72 2e 65 78 65 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {4e 00 4a 00 43 00 72 00 79 00 70 00 74 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}