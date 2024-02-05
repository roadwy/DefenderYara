
rule TrojanDownloader_BAT_RaccoonStealerV2_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/RaccoonStealerV2.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13 } //02 00 
		$a_01_1 = {61 d2 9c 06 17 25 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}