
rule Trojan_BAT_PureLogStealer_PCAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.PCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 08 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 5b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d } //2
		$a_03_1 = {13 09 11 08 11 09 16 1a 6f ?? 00 00 0a 26 11 09 16 28 ?? 00 00 0a 13 0a 11 08 16 73 ?? 00 00 0a 13 0b 11 0b 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0a } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}