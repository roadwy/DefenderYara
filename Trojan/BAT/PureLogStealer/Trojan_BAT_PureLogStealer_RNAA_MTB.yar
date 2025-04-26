
rule Trojan_BAT_PureLogStealer_RNAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 08 6f ?? 00 00 0a 73 ?? 00 00 0a 13 06 1a 8d ?? 00 00 01 13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 ?? 00 00 0a 13 09 11 09 11 05 6f ?? 00 00 0a 73 ?? 00 00 0a 13 0a 11 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 11 0a 13 0a de 4e } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}