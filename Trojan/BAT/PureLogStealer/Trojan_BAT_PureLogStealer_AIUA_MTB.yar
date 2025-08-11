
rule Trojan_BAT_PureLogStealer_AIUA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AIUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 05 07 08 16 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 07 08 17 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 07 08 18 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 08 17 58 0c 11 04 17 58 13 04 11 04 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 ab } //5
		$a_03_1 = {03 07 11 06 16 28 ?? 00 00 0a 6f ?? 00 00 0a 03 07 11 06 17 28 ?? 00 00 0a 6f ?? 00 00 0a 03 07 11 06 18 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 26 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}