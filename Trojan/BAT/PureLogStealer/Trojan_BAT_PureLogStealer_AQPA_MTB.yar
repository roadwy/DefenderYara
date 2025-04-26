
rule Trojan_BAT_PureLogStealer_AQPA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AQPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 1b 2b 1c 2b 21 73 ?? 00 00 0a 25 72 ?? ?? 00 70 2b 17 2b 1c 2b 1d 2b 22 2b 27 de 2d 02 2b e2 28 ?? 00 00 06 2b dd 0a 2b dc 28 ?? 00 00 0a 2b e2 06 2b e1 28 ?? 00 00 06 2b dc 6f ?? 00 00 0a 2b d7 0b 2b d6 } //3
		$a_01_1 = {08 02 59 07 59 20 ff 00 00 00 25 2c f7 5f 16 2d 15 d2 0c 08 66 16 2d ed d2 0c 06 07 08 9c 07 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}