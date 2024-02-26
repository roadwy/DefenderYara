
rule TrojanDownloader_BAT_zgRAT_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 11 02 72 90 01 01 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 26 20 90 00 } //02 00 
		$a_01_1 = {04 03 04 58 11 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}