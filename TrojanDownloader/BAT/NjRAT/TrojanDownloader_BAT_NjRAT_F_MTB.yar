
rule TrojanDownloader_BAT_NjRAT_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/NjRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 04 07 08 16 6f 90 01 01 01 00 0a 13 05 12 05 28 90 00 } //02 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //00 00  WebClient
	condition:
		any of ($a_*)
 
}