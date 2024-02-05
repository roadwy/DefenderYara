
rule TrojanDownloader_BAT_AgentTesla_NSW_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {3a 5e 5e 5e 5e 5e 23 23 23 23 5e 5e 5e 5e 5e 23 23 23 23 62 6c 75 65 63 6f 76 65 72 74 72 61 64 69 6e 67 2e 63 6f 6d 2f 73 2f } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_2 = {52 52 55 55 4e 4e 4e } //01 00 
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00 
		$a_81_5 = {59 45 57 48 53 48 4a 53 4a 55 49 53 59 55 53 } //00 00 
	condition:
		any of ($a_*)
 
}