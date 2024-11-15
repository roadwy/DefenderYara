
rule Trojan_BAT_DarkTortilla_SEDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 08 6f ?? ?? ?? 0a 00 11 06 08 6f ?? ?? ?? 0a 00 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? ?? ?? 0a 17 73 ?? 01 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 08 6f ?? ?? ?? 0a 00 11 07 6f ?? ?? ?? 0a 0d de 0e } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}