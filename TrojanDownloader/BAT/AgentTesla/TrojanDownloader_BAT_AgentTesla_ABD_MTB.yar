
rule TrojanDownloader_BAT_AgentTesla_ABD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 0a 02 06 28 90 01 03 06 0b 07 2a 90 0a 16 00 02 72 90 01 03 70 28 04 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}