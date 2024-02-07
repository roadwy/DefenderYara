
rule TrojanDownloader_BAT_AgentTesla_NYD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 39 00 00 01 25 19 6f 49 00 00 0a 6f 4a 00 00 0a 74 14 00 00 01 0a 06 6f 4b 00 00 0a 0b 07 73 4c 00 00 0a 0c 08 6f 4d 00 00 0a 0d de 27 } //01 00 
		$a_01_1 = {3f a2 1d 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 51 00 00 00 18 00 00 00 23 00 00 00 54 00 00 00 3d 00 00 00 03 00 00 00 9a 00 00 00 07 } //01 00 
		$a_01_2 = {56 69 64 65 6f 50 6c 61 79 65 72 } //00 00  VideoPlayer
	condition:
		any of ($a_*)
 
}