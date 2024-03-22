
rule Trojan_BAT_Njrat_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Njrat.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 14 fe 01 38 90 01 04 07 73 90 01 01 00 00 0a 21 90 01 08 28 90 01 01 00 00 0a 21 90 01 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 73 90 01 01 00 00 0a 16 73 90 01 01 00 00 0a 13 04 17 2b a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}