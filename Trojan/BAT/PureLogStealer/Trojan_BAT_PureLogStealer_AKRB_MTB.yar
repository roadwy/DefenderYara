
rule Trojan_BAT_PureLogStealer_AKRB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AKRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 2b 00 2b 00 09 07 28 ?? ?? 00 06 00 00 09 6f ?? ?? 00 0a 13 04 2b 00 11 04 02 28 ?? ?? 00 06 0a dd } //4
		$a_03_1 = {11 0e 11 1e 94 11 0f 11 1e 94 d6 11 0d da 13 1f 2b 00 11 11 11 1f 28 ?? 00 00 0a 6f ?? 00 00 0a 26 11 1e 17 d6 13 1e 11 1e 11 1d 31 d3 } //2
		$a_03_2 = {02 03 16 03 8e 69 6f ?? ?? 00 0a 0b 07 28 } //2
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=9
 
}