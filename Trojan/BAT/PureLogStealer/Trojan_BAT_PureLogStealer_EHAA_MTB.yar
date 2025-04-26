
rule Trojan_BAT_PureLogStealer_EHAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.EHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 20 00 04 00 00 2e f0 08 15 3e ?? 00 00 00 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}