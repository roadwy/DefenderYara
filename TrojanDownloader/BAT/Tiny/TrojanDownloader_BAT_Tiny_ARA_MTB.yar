
rule TrojanDownloader_BAT_Tiny_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c 90 01 03 00 11 04 11 06 59 38 90 01 03 00 20 00 10 00 00 16 6f 90 01 03 0a 58 13 06 11 06 11 04 3f 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}