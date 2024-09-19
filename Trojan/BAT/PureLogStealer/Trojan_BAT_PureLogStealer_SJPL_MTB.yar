
rule Trojan_BAT_PureLogStealer_SJPL_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SJPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 73 0f 00 00 0a 0c 08 07 17 73 14 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 6f ?? 00 00 0a 16 11 04 6f ?? 00 00 0a 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 08 13 05 dd 1a 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}