
rule Trojan_BAT_RedLineStealer_KAH_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {a2 07 08 9a 7e 90 01 01 00 00 04 28 90 01 02 00 06 08 17 58 0c 08 07 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}