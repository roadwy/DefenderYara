
rule Trojan_BAT_PureLogStealer_GTAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.GTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {38 2b 00 00 00 11 03 16 11 03 8e 69 28 90 01 01 00 00 0a 20 00 00 00 00 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}