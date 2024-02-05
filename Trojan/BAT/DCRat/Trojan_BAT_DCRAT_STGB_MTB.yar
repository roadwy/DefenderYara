
rule Trojan_BAT_DCRAT_STGB_MTB{
	meta:
		description = "Trojan:BAT/DCRAT.STGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 04 11 09 28 90 01 03 06 25 26 7b cb 00 00 04 11 0a 91 28 90 01 03 06 11 0a 13 0b 11 0b 1f 0c 28 90 01 03 06 58 13 0a 11 0a 7e 05 00 00 04 11 09 28 90 01 03 06 25 26 7b cb 00 00 04 28 90 01 03 06 25 26 69 32 b6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}