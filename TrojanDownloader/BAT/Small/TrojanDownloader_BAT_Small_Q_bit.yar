
rule TrojanDownloader_BAT_Small_Q_bit{
	meta:
		description = "TrojanDownloader:BAT/Small.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //01 00 
		$a_00_1 = {3e 00 28 00 2e 00 2a 00 29 00 2b 00 29 00 } //01 00 
		$a_02_2 = {5c 00 74 00 6d 00 70 00 5c 00 69 00 64 00 90 02 08 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}