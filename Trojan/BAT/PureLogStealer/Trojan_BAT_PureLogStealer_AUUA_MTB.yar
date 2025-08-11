
rule Trojan_BAT_PureLogStealer_AUUA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AUUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 32 29 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 47 11 09 16 31 42 } //5
		$a_03_1 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}