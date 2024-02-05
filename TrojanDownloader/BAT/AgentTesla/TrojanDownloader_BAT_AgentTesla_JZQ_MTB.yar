
rule TrojanDownloader_BAT_AgentTesla_JZQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.JZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 52 75 6e 50 45 2e 64 6c 6c } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_3 = {52 75 6e 50 45 2e 52 75 6e 50 45 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}