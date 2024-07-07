
rule Trojan_BAT_DarkTortilla_AAXL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 1f 20 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 09 08 1f 10 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 09 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 00 73 90 01 01 00 00 0a 13 05 00 11 05 11 04 17 73 90 01 01 00 00 0a 13 07 11 07 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 11 07 6f 90 01 01 00 00 0a 00 de 0e 00 11 07 2c 08 11 07 6f 90 01 01 00 00 0a 00 dc 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}