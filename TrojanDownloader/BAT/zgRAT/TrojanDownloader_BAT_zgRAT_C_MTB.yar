
rule TrojanDownloader_BAT_zgRAT_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 08 06 91 11 90 01 01 06 11 90 01 01 6f 90 01 02 00 0a 5d 6f 90 01 02 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}