
rule Trojan_BAT_PureLogStealer_DMAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.DMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 07 17 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 0c 11 0c 11 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 0d 90 00 } //2
		$a_03_1 = {13 0e 11 0d 11 0e 16 11 0e 8e 69 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 0c 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c de 24 90 00 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}