
rule Trojan_BAT_PureLogStealer_KEAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 02 16 3e 19 00 00 00 02 18 5d 3a 11 00 00 00 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 28 ?? 00 00 0a 28 ?? 00 00 0a 06 6f } //5
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}