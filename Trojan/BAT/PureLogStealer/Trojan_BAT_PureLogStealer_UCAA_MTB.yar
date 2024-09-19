
rule Trojan_BAT_PureLogStealer_UCAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.UCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 61 00 00 70 28 ?? 00 00 0a 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a dd } //4
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}