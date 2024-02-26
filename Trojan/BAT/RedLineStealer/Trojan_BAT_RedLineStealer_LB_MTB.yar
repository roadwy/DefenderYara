
rule Trojan_BAT_RedLineStealer_LB_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.LB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e 38 29 90 01 02 0e 06 17 59 e0 95 58 0e 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}