
rule Trojan_BAT_PureLogStealer_FLAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.FLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 58 0b 08 17 58 0c 08 02 31 f4 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}