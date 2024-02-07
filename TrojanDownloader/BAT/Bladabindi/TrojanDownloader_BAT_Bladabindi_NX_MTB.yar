
rule TrojanDownloader_BAT_Bladabindi_NX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 00 13 67 00 6e 00 69 00 72 00 74 00 53 00 64 00 61 00 6f 00 00 03 20 00 00 0b 6c 00 6e 00 77 00 6f 00 44 00 00 0f 49 00 49 00 49 00 49 00 49 00 49 00 49 } //01 00 
		$a_01_1 = {49 00 00 03 6e 00 00 03 51 00 00 03 76 00 00 03 6f 00 00 03 6b 00 00 11 2b 00 2d 00 2b 00 2d 00 2b 00 2d 00 2b } //01 00 
		$a_01_2 = {0a 26 09 17 d6 0d 09 08 8e 69 32 } //01 00 
		$a_81_3 = {64 61 6f 4c } //01 00  daoL
		$a_81_4 = {6d 6f 63 2e 6e 69 62 65 74 73 61 70 } //01 00  moc.nibetsap
		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_6 = {2f 77 61 72 2f 40 35 38 45 43 33 30 41 39 43 32 33 32 33 30 35 36 34 43 40 } //01 00  /war/@58EC30A9C23230564C@
		$a_81_7 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}