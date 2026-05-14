
rule Trojan_BAT_PureLogStealer_MXP_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 05 1b 13 23 2b aa 19 2b f9 7e ff 02 00 04 2b 16 7e e1 02 00 04 fe 06 c3 05 00 06 73 06 02 00 0a 25 80 ff 02 00 04 13 0a 00 11 09 6f ?? 02 00 0a 13 0b 2b 00 2b 00 18 13 25 11 25 } //5
		$a_03_1 = {2b 00 02 11 0a 07 6f ?? 02 00 0a 11 0b 6f ?? 02 00 0a 6f ?? 01 00 0a 00 de 45 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}