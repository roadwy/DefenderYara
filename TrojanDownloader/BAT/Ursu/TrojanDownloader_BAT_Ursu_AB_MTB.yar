
rule TrojanDownloader_BAT_Ursu_AB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ursu.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 07 11 04 28 90 01 01 00 00 0a 16 6f 90 01 01 00 00 0a 13 08 12 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 04 11 06 12 04 28 90 01 01 00 00 0a 13 09 11 09 2d d1 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 14 14 6f 90 01 01 00 00 0a 26 de 2b 90 00 } //01 00 
		$a_01_1 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {54 6f 49 6e 74 65 67 65 72 } //01 00  ToInteger
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_5 = {46 72 6f 6d 53 74 72 65 61 6d } //00 00  FromStream
	condition:
		any of ($a_*)
 
}