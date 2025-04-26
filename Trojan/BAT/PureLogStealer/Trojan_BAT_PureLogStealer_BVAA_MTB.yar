
rule Trojan_BAT_PureLogStealer_BVAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.BVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 17 58 0b 1c 2c ?? 07 1b 32 ?? 2a 0a 38 ?? ff ff ff 28 ?? 00 00 06 38 ?? ff ff ff 0a 38 ?? ff ff ff 0b 38 ?? ff ff ff 06 38 ?? ff ff ff 28 ?? 00 00 2b 38 ?? ff ff ff 28 ?? 00 00 2b 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 02 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}