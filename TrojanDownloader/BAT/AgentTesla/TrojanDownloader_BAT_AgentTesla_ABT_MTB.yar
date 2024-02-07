
rule TrojanDownloader_BAT_AgentTesla_ABT_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 0a 06 2a 90 0a 12 00 72 59 90 01 02 70 28 10 90 01 02 06 28 12 90 00 } //05 00 
		$a_03_1 = {07 08 16 11 05 6f 90 01 03 0a 06 08 16 08 8e 69 6f 90 01 03 0a 25 13 05 16 fe 03 2d e3 07 6f 90 01 03 0a 13 06 de 0a 90 00 } //01 00 
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //00 00  WebClient
	condition:
		any of ($a_*)
 
}