
rule Trojan_BAT_VIPKeylogger_ZSR_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ZSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 7e ?? 01 00 04 2c 07 7e ?? 01 00 04 2b 16 7e ?? 01 00 04 fe ?? 48 01 00 06 73 ?? 02 00 0a 25 80 ?? 01 00 04 13 0a 00 11 09 6f ?? 02 00 0a 13 0b 02 11 0a 07 6f ?? 02 00 0a 11 0b 6f ?? 02 00 0a 6f ?? 01 00 0a 00 de 0e } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}