
rule Trojan_BAT_Dcstl_ZHAA_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.ZHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 73 ?? 00 00 0a 13 04 11 04 11 07 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0c 00 00 de 39 } //3
		$a_01_1 = {4c 00 20 00 6f 00 20 00 61 00 20 00 64 00 } //1 L o a d
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}