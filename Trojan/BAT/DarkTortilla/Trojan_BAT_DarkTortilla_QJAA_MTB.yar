
rule Trojan_BAT_DarkTortilla_QJAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.QJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0c 07 14 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 08 28 ?? 01 00 06 28 ?? 00 00 06 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 06 28 ?? 01 00 06 00 de 10 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}