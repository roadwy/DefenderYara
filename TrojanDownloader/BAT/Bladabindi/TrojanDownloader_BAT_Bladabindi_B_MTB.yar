
rule TrojanDownloader_BAT_Bladabindi_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 04 07 08 16 6f 90 01 01 00 00 0a 13 05 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 08 17 d6 0c 08 11 04 13 06 11 06 90 00 } //01 00 
		$a_01_1 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_3 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}