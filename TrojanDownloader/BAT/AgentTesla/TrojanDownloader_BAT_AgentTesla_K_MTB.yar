
rule TrojanDownloader_BAT_AgentTesla_K_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 25 26 25 16 20 90 01 01 00 00 00 28 90 01 01 00 00 06 90 02 02 a2 25 17 7e 90 01 01 00 00 0a a2 25 18 11 06 a2 25 19 17 8c 90 01 01 00 00 01 a2 13 08 11 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}