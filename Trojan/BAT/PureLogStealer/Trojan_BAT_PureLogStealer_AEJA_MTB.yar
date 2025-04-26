
rule Trojan_BAT_PureLogStealer_AEJA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AEJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 72 f8 00 00 70 28 ?? 00 00 0a 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 08 06 09 06 08 91 9c 06 08 11 08 9c dd } //3
		$a_03_1 = {06 08 91 06 09 91 58 72 f8 00 00 70 28 ?? 00 00 0a 5d 13 06 73 ?? 00 00 0a 13 07 11 07 06 11 06 91 6f ?? 00 00 0a 02 11 05 8f ?? 00 00 01 25 47 11 07 16 6f ?? 00 00 0a 61 d2 52 11 05 17 58 13 05 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}