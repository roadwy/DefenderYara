
rule TrojanDownloader_BAT_AgentTesla_ESI_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 47 46 46 51 46 46 44 53 46 57 51 46 57 51 46 57 51 00 } //01 00 
		$a_01_1 = {00 66 64 67 66 64 67 66 64 67 67 00 } //01 00  昀杤摦晧杤g
		$a_01_2 = {00 47 46 46 51 46 57 51 46 57 51 46 57 51 00 } //01 00 
		$a_01_3 = {00 47 65 74 4d 65 74 68 6f 64 00 77 71 64 00 } //01 00 
		$a_01_4 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //01 00 
		$a_01_5 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00 } //01 00  䐀睯汮慯䑤瑡a
		$a_01_6 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_7 = {00 52 65 76 65 72 73 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}