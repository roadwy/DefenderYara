
rule Trojan_BAT_DarkTortilla_OSAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.OSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 73 ?? 01 00 0a 0d 09 11 06 17 73 ?? 01 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 01 00 0a 00 11 04 6f ?? 01 00 0a 00 09 6f ?? 01 00 0a 0c de 1c } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}