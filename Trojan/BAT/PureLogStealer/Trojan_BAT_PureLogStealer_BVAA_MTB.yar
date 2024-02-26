
rule Trojan_BAT_PureLogStealer_BVAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.BVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 17 58 0b 1c 2c 90 01 01 07 1b 32 90 01 01 2a 0a 38 90 01 01 ff ff ff 28 90 01 01 00 00 06 38 90 01 01 ff ff ff 0a 38 90 01 01 ff ff ff 0b 38 90 01 01 ff ff ff 06 38 90 01 01 ff ff ff 28 90 01 01 00 00 2b 38 90 01 01 ff ff ff 28 90 01 01 00 00 2b 38 90 01 01 ff ff ff 28 90 01 01 00 00 0a 38 90 01 01 ff ff ff 02 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}