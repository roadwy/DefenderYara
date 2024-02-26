
rule TrojanDownloader_BAT_RevengeRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/RevengeRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 17 9a 75 90 01 01 00 00 01 20 90 01 03 1a 28 90 01 02 00 06 20 00 01 00 00 14 14 14 6f 90 01 02 00 0a a2 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}