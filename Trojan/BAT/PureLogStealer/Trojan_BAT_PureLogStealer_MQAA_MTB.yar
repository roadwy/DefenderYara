
rule Trojan_BAT_PureLogStealer_MQAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 73 90 01 01 00 00 0a 0b 11 04 73 90 01 01 00 00 0a 0c 08 11 05 16 73 90 01 01 00 00 0a 0d 2b 0a 2b 0b 2b 0c 2b 11 2b 12 de 32 09 2b f3 07 2b f2 6f 90 01 01 00 00 0a 2b ed 90 00 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}