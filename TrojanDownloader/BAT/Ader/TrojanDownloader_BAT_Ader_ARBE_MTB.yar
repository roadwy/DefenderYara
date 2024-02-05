
rule TrojanDownloader_BAT_Ader_ARBE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 03 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}