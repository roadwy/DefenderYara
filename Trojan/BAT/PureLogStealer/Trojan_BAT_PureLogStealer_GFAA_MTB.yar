
rule Trojan_BAT_PureLogStealer_GFAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.GFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 16 11 05 8e 69 28 90 01 01 00 00 0a 20 00 00 00 00 7e 90 01 01 1d 00 04 7b 90 01 01 1d 00 04 3a 90 01 01 ff ff ff 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}