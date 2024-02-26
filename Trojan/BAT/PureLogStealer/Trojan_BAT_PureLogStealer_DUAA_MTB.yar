
rule Trojan_BAT_PureLogStealer_DUAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.DUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 01 11 02 58 13 01 20 07 00 00 00 7e 90 01 01 00 00 04 7b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}