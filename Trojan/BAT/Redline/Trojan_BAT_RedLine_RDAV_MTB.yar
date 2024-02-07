
rule Trojan_BAT_RedLine_RDAV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 31 63 63 32 62 61 64 2d 64 36 66 37 2d 34 37 62 38 2d 61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //01 00  d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1
		$a_01_1 = {44 69 73 63 6f 72 64 } //02 00  Discord
		$a_01_2 = {11 10 1f 0f 5f 11 0d 11 10 1f 0f 5f 95 11 06 25 1a 58 13 06 4b 61 } //00 00 
	condition:
		any of ($a_*)
 
}