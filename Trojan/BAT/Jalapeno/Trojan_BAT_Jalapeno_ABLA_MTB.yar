
rule Trojan_BAT_Jalapeno_ABLA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ABLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2c 2b 2d 2b 2e 08 07 6f ?? 04 00 0a 08 6f ?? 04 00 0a 0d 73 ?? 04 00 0a 25 09 02 16 02 8e 69 6f ?? 03 00 0a 6f ?? 04 00 0a 13 04 de 1a 08 2b d1 06 2b d0 6f ?? 04 00 0a 2b cb } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}