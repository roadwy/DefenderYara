
rule TrojanDownloader_BAT_AgentTesla_LTB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 62 75 79 73 72 69 6c 61 6e 6b 61 6e 2e 6c 6b 2f 70 70 2f 43 6f 6e 73 6f 6c 65 41 70 70 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_5 = {47 65 74 54 79 70 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}