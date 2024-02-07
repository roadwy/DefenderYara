
rule TrojanDownloader_BAT_AgentTesla_ABG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 03 0c 2b 00 07 16 73 03 90 01 02 0a 73 04 90 01 02 0a 0d 09 08 6f 05 90 01 02 0a de 07 09 6f 06 90 01 02 0a dc 08 6f 07 90 01 02 0a 13 04 de 0e 90 0a 55 00 72 01 90 01 02 70 28 02 90 01 02 06 18 2d 0d 26 06 73 01 90 01 02 0a 18 2d 06 26 2b 06 0a 2b f1 0b 2b 00 73 02 90 01 02 0a 1b 2d 03 26 90 00 } //01 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}