
rule Trojan_BAT_Zilla_NITC_MTB{
	meta:
		description = "Trojan:BAT/Zilla.NITC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 73 10 00 00 0a 0b 07 72 61 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0a dd 0d 00 00 00 07 39 06 00 00 00 07 6f ?? 00 00 0a dc dd 03 00 00 00 26 de bf } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}