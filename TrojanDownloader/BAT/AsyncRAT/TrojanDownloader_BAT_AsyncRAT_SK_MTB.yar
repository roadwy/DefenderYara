
rule TrojanDownloader_BAT_AsyncRAT_SK_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 0d 11 04 11 06 58 17 58 17 59 11 05 11 07 58 17 58 17 59 6f 90 01 03 0a 13 16 12 16 28 90 01 03 0a 13 10 11 0c 11 08 11 10 9c 11 08 17 58 13 08 11 07 17 58 13 07 11 07 17 fe 04 13 11 11 11 2d be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}