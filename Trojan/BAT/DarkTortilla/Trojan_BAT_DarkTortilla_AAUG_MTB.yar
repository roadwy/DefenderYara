
rule Trojan_BAT_DarkTortilla_AAUG_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 11 04 74 ?? 00 00 1b 6f ?? 01 00 0a 1a 13 0c 2b b3 11 05 74 ?? 00 00 01 11 05 74 ?? 00 00 01 6f ?? 01 00 0a 11 05 75 ?? 00 00 01 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 1c 13 0c 2b 88 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}