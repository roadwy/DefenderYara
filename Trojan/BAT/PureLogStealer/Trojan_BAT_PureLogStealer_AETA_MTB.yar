
rule Trojan_BAT_PureLogStealer_AETA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AETA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 08 28 ?? 00 00 06 0d 09 8d ?? 00 00 01 13 04 08 16 73 ?? 00 00 0a 13 05 02 11 05 11 04 16 09 28 ?? 00 00 06 dd 0f 00 00 00 11 05 39 07 00 00 00 11 05 6f ?? 00 00 0a dc 03 72 c7 00 00 70 11 04 6f ?? 00 00 06 17 0b dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}