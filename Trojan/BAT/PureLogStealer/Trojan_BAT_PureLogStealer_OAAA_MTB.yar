
rule Trojan_BAT_PureLogStealer_OAAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.OAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 2d 04 2b 04 2b 09 de 0d 28 ?? 00 00 06 2b f5 0a 2b f4 26 de 00 } //2
		$a_03_1 = {16 13 05 11 04 12 05 28 ?? 00 00 0a 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0c 11 05 2c 07 11 04 28 ?? 00 00 0a dc } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}