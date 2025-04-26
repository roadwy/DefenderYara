
rule Trojan_BAT_PureLogStealer_NYAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 } //2
		$a_03_1 = {11 07 06 16 06 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 11 08 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}