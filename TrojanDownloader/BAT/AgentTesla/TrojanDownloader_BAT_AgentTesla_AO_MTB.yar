
rule TrojanDownloader_BAT_AgentTesla_AO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f 1e 90 01 02 0a 00 11 04 6f 1f 90 01 02 0a 80 01 90 01 02 04 16 13 05 2b 1f 90 0a 47 00 20 00 90 01 02 00 28 19 90 01 02 0a 00 72 01 90 01 02 70 0a 06 28 1a 90 01 02 0a 0b 07 6f 1b 90 01 02 0a 0c 08 6f 1c 90 01 02 0a 0d 73 1d 90 01 02 0a 13 04 90 00 } //01 00 
		$a_01_1 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {54 6f 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}