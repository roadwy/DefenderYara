
rule TrojanDownloader_BAT_Zegost_A{
	meta:
		description = "TrojanDownloader:BAT/Zegost.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 61 00 78 00 31 00 32 00 33 00 34 00 } //01 00 
		$a_02_1 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 31 00 32 00 33 00 34 00 2e 00 6d 00 69 00 72 00 65 00 65 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 2f 00 68 00 74 00 6d 00 6c 00 2f 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_00_2 = {63 00 3a 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f 00 73 00 79 00 73 00 2e 00 69 00 6e 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}