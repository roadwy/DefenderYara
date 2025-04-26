
rule Trojan_BAT_Crysan_AAIO_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 6f ?? 00 00 0a 11 04 07 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 02 28 ?? 00 00 0a 73 ?? 00 00 0a 13 06 11 06 11 05 16 73 ?? 00 00 0a 13 07 11 07 73 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 0a dd ?? 00 00 00 11 08 39 ?? 00 00 00 11 08 6f ?? 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}