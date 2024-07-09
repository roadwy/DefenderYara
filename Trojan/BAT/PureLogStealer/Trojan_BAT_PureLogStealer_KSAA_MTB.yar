
rule Trojan_BAT_PureLogStealer_KSAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0a 16 11 0a 8e 69 6f ?? 00 00 0a 13 07 20 00 00 00 00 28 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}