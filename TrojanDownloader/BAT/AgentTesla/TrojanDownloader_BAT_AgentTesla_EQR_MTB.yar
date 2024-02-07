
rule TrojanDownloader_BAT_AgentTesla_EQR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f 90 01 03 0a 08 25 17 59 0c 16 fe 02 0d 09 90 00 } //01 00 
		$a_01_1 = {0a 12 00 23 00 00 00 00 00 00 34 40 28 } //01 00 
		$a_01_2 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00 } //01 00  䐀睯汮慯䑤瑡a
		$a_01_3 = {00 47 65 74 4d 65 74 68 6f 64 00 } //01 00 
		$a_01_4 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}