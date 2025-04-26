
rule Trojan_BAT_PureLogStealer_HUAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 15 31 0c 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 28 ?? ?? 00 0a 07 6f ?? ?? 00 0a 0d 07 2c 2b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}