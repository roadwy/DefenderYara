
rule TrojanDownloader_BAT_AgentTesla_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 11 06 a2 25 1f 14 28 90 01 01 00 00 2b 1f 18 28 90 01 01 00 00 2b 8c 90 01 01 00 00 01 a2 13 90 09 16 00 a2 25 1f 90 01 01 28 90 01 01 00 00 2b 7e 90 01 01 00 00 0a a2 25 1f 10 28 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {52 65 61 64 54 6f 45 6e 64 } //01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}