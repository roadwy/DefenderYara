
rule Trojan_BAT_PureLogStealer_ABRB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ABRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a ?? 13 0b 2b bd 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 } //4
		$a_03_1 = {11 07 02 16 02 8e 69 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a ?? 13 0f 2b c6 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}