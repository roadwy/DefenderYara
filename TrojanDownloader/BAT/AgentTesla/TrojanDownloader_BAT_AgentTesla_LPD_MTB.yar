
rule TrojanDownloader_BAT_AgentTesla_LPD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 56 59 55 59 44 55 59 46 55 46 48 48 4a 46 4a } //01 00 
		$a_81_1 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_81_4 = {76 34 2e 30 2e 33 30 33 31 39 5c 74 68 65 64 65 76 69 6c 63 6f 64 65 72 2e 65 78 65 } //01 00 
		$a_01_5 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_6 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}