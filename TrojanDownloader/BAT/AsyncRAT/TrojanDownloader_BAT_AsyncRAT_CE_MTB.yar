
rule TrojanDownloader_BAT_AsyncRAT_CE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0a 02 50 8e 69 17 59 0b 38 } //02 00 
		$a_01_1 = {02 50 06 91 0c 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 } //00 00 
	condition:
		any of ($a_*)
 
}