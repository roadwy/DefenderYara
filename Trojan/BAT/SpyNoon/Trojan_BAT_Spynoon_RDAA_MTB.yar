
rule Trojan_BAT_Spynoon_RDAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 02 28 ?? 00 00 06 0b 73 49 00 00 0a 25 06 6f ?? 00 00 0a 25 07 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0d de 0a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}