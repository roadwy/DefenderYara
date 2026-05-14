
rule Trojan_BAT_PureLogStealer_RVB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 7b cf 00 00 04 09 11 04 6f ?? 00 00 0a 13 08 19 8d ?? 00 00 01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ce 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c } //1
		$a_81_1 = {31 32 33 34 35 36 37 38 2d 31 32 33 34 2d 31 32 33 34 2d 31 32 33 34 2d 31 32 33 34 35 36 37 38 39 61 62 63 } //1 12345678-1234-1234-1234-123456789abc
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}