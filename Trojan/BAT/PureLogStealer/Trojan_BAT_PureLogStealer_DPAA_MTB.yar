
rule Trojan_BAT_PureLogStealer_DPAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.DPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 06 58 0d 06 17 58 0a 06 02 31 f4 } //2
		$a_03_1 = {20 00 01 00 00 14 14 14 6f 90 01 02 00 0a 26 11 04 07 5a 13 04 07 17 58 0b 07 02 31 d8 90 00 } //2
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}