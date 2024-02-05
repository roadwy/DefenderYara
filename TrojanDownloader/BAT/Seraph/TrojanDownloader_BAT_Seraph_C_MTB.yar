
rule TrojanDownloader_BAT_Seraph_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 00 17 58 13 00 38 } //01 00 
		$a_02_1 = {11 00 1f 16 3f 90 01 04 38 90 00 } //01 00 
		$a_01_2 = {16 13 00 38 } //01 00 
		$a_02_3 = {06 25 14 fe 06 90 01 03 06 73 90 01 03 06 6f 90 01 03 06 6f 90 01 03 06 38 90 00 } //01 00 
		$a_02_4 = {0a 13 01 38 00 00 00 00 11 00 11 01 6f 90 01 03 0a 38 00 00 00 00 11 01 90 01 05 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 13 02 38 00 00 00 00 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}