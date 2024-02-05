
rule TrojanDownloader_BAT_AsyncRAT_AE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {04 8e 69 5d 91 02 11 02 91 61 d2 6f } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00 
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_3 = {67 65 74 5f 41 53 43 49 49 } //00 00 
	condition:
		any of ($a_*)
 
}