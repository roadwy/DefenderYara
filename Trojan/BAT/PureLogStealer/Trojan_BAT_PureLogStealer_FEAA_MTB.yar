
rule Trojan_BAT_PureLogStealer_FEAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.FEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 14 0d 28 90 01 01 00 00 0a 2c 0d 08 28 90 01 01 00 00 0a 08 28 90 01 01 00 00 0a 0d 90 00 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}