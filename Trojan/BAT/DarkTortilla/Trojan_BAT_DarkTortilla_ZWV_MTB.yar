
rule Trojan_BAT_DarkTortilla_ZWV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 2b 50 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 01 00 0a 0b 00 73 ?? 01 00 0a 0d 09 07 28 ?? 01 00 06 00 00 09 6f ?? 01 00 0a 13 04 11 04 02 28 ?? 01 00 06 0a de 1a 00 11 04 2c 08 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}