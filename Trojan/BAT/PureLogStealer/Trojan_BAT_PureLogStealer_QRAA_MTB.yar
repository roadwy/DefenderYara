
rule Trojan_BAT_PureLogStealer_QRAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.QRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 01 20 9f ab a6 d6 28 ?? 05 00 06 28 ?? 04 00 0a 20 bc ab a6 d6 28 ?? 06 00 06 28 ?? 06 00 06 6f ?? 05 00 0a 13 06 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}