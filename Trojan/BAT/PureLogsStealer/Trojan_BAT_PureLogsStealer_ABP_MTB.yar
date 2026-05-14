
rule Trojan_BAT_PureLogsStealer_ABP_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8c 03 00 00 1b 03 04 6f ?? 01 00 0a 0b 11 05 20 ba 00 00 00 93 20 ?? 62 00 00 59 13 04 38 ?? ff ff ff 06 17 58 0a 0e 04 25 5a 0e 04 58 18 5d 2c 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}