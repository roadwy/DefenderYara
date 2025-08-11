
rule Trojan_BAT_PureLogStealer_AYRA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AYRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 03 8e 69 1a 59 8d ?? 00 00 01 0b 03 1a 07 16 07 8e 69 28 ?? 00 00 0a 06 28 ?? 00 00 06 0c 07 73 ?? 00 00 0a 0d 09 16 73 ?? 00 00 0a 13 04 16 13 05 38 ?? 00 00 00 11 04 08 11 05 06 11 05 59 6f ?? 00 00 0a 13 06 11 06 39 ?? 00 00 00 11 05 11 06 58 13 05 11 05 06 32 dd 11 05 06 3b ?? 00 00 00 73 ?? 00 00 0a 7a 06 8d ?? 00 00 01 13 07 08 16 11 07 16 06 28 ?? 00 00 0a 11 07 13 08 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}