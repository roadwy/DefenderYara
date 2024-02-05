
rule Trojan_BAT_Redline_GTC_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 17 58 0a 06 1f 0f 34 12 02 06 58 03 06 58 46 06 1f 3b 5e 1f 37 58 61 52 2b e5 } //0a 00 
		$a_01_1 = {11 06 12 1a 58 11 06 25 1f 3b 5c 1f 3b 5a 59 1f 32 58 11 06 12 1a 58 46 61 52 11 06 17 58 13 06 11 06 1f 12 37 da } //01 00 
		$a_01_2 = {50 72 6f 6a 65 63 74 33 35 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}