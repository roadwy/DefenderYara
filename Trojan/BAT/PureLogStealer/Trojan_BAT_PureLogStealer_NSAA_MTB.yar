
rule Trojan_BAT_PureLogStealer_NSAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 11 05 20 00 01 00 00 6f ?? 00 00 0a 11 05 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 } //2
		$a_03_1 = {1a 8d 1d 00 00 01 13 0b 11 0a 11 0b 16 1a 6f ?? 00 00 0a 26 11 0b 16 28 ?? 00 00 0a 26 11 0a 16 73 ?? 00 00 0a 13 0c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}