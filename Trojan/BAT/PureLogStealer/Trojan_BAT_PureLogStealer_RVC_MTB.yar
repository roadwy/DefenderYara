
rule Trojan_BAT_PureLogStealer_RVC_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 38 c0 01 00 00 00 06 7b ?? 00 00 04 09 11 04 6f ?? 00 00 0a 13 08 19 8d ?? 00 00 01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a } //2
		$a_03_1 = {28 13 00 00 2b 13 0a 07 6f ?? 00 00 0a 03 fe 04 13 0b 11 0b 2c 0d 00 07 11 0a 16 91 6f ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 03 fe 04 13 0c 11 0c 2c 0d 00 07 11 0a 17 91 6f ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 03 fe 04 13 0d 11 0d 2c 0d 00 07 11 0a 18 91 6f ?? 00 00 0a 00 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}