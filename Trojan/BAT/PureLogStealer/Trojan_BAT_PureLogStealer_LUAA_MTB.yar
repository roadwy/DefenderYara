
rule Trojan_BAT_PureLogStealer_LUAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.LUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0e 17 58 11 07 5d 13 11 11 06 11 0e 91 11 10 61 11 06 11 11 91 59 13 12 11 12 20 00 01 00 00 58 13 13 11 06 11 0e 11 13 20 ff 00 00 00 5f d2 9c 00 11 0e 17 58 13 0e } //00 00 
	condition:
		any of ($a_*)
 
}