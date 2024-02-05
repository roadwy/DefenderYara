
rule TrojanDownloader_BAT_Seraph_MR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 06 00 "
		
	strings :
		$a_02_0 = {06 09 06 6f 90 02 04 1e 5b 6f 90 02 04 6f 90 02 04 06 09 06 6f 90 02 04 1e 5b 6f 90 02 04 6f 90 02 04 06 17 6f 90 02 04 07 06 6f 90 02 04 17 90 00 } //01 00 
		$a_81_1 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //01 00 
		$a_81_2 = {73 65 74 5f 49 56 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_4 = {67 65 74 5f 55 54 46 38 } //01 00 
		$a_81_5 = {73 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 } //00 00 
	condition:
		any of ($a_*)
 
}