
rule TrojanDownloader_BAT_Agent_Q{
	meta:
		description = "TrojanDownloader:BAT/Agent.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {5c 64 6f 74 6e 65 74 5c 67 61 69 62 61 6e 5c 90 02 40 73 64 62 2e 70 64 62 90 00 } //01 00 
		$a_00_1 = {53 00 50 00 4f 00 4f 00 4c 00 53 00 56 00 43 00 } //01 00 
		$a_00_2 = {2e 00 62 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 6d 00 65 00 3a 00 38 00 30 00 38 00 30 00 2f 00 77 00 65 00 62 00 43 00 6c 00 6f 00 75 00 64 00 2f 00 } //01 00 
		$a_00_3 = {4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}