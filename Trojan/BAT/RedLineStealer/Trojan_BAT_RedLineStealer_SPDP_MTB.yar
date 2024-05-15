
rule Trojan_BAT_RedLineStealer_SPDP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 7e 01 00 00 04 6f 90 01 03 06 8e 69 20 90 01 03 00 1f 40 28 90 01 03 06 0a 16 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}