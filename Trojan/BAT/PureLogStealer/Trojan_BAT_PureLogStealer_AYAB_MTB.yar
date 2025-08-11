
rule Trojan_BAT_PureLogStealer_AYAB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AYAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 14 13 04 38 be 00 00 00 00 20 00 0c 00 00 28 ?? 00 00 0a dd ?? 00 00 00 26 dd 00 00 00 00 73 ?? 00 00 0a 13 05 11 05 72 ?? 00 00 70 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 13 07 11 06 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 04 dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}