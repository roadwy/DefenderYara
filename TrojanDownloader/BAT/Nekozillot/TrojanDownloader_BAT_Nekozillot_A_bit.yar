
rule TrojanDownloader_BAT_Nekozillot_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Nekozillot.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 00 69 00 6c 00 6c 00 6f 00 74 00 2e 00 6b 00 7a 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00 
		$a_01_1 = {7a 00 69 00 6c 00 6c 00 6f 00 74 00 5f 00 6e 00 65 00 6b 00 6f 00 } //01 00 
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}