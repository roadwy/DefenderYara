
rule TrojanDownloader_BAT_AgentTesla_ANLL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ANLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 04 11 06 9a 17 8d 27 00 00 01 25 16 1f 3a 9d 6f 90 01 03 0a 13 07 11 07 16 9a 11 07 17 9a 28 90 00 } //01 00 
		$a_01_1 = {4d 00 65 00 67 00 61 00 2e 00 4e 00 5a 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64 00 } //01 00 
		$a_01_2 = {43 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 20 00 44 00 6f 00 6e 00 65 00 21 00 } //01 00 
		$a_01_3 = {68 00 69 00 74 00 73 00 20 00 69 00 6e 00 20 00 68 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}