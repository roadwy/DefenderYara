
rule Trojan_BAT_PureLogStealer_NC_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 6f 67 00 00 0a 26 2b 2f 28 1a 00 00 0a 6f 83 00 00 0a 6f 84 00 00 0a 25 2c 03 17 2b 03 16 2b 00 2d 06 73 85 00 00 0a 7a 11 0a 1f 0c 58 11 0c 16 11 0b 28 86 00 00 0a } //2
		$a_01_1 = {73 0b 00 00 0a 13 07 11 05 18 5f 2c 03 16 2b 03 17 2b 00 3a 91 00 00 00 06 6f 87 00 00 0a 11 06 6f 88 00 00 0a 16 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}