
rule Trojan_BAT_Mardom_AABA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 07 28 ?? 00 00 06 73 ?? 00 00 0a 13 05 09 11 05 09 6f ?? 00 00 0a 28 ?? 00 00 06 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 05 09 6f ?? 00 00 0a 28 ?? 00 00 06 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 28 ?? 00 00 06 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 28 ?? 00 00 06 73 ?? 00 00 0a 13 06 11 06 02 28 ?? 00 00 06 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a de 0c } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}