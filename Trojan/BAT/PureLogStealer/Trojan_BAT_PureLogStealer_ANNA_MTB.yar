
rule Trojan_BAT_PureLogStealer_ANNA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ANNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de 1f } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}