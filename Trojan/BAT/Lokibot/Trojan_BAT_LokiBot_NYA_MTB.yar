
rule Trojan_BAT_LokiBot_NYA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 00 59 00 48 00 47 00 44 00 52 00 57 00 55 00 49 00 59 00 47 00 46 00 49 00 46 00 57 00 48 00 49 00 55 00 57 00 46 00 48 00 46 00 57 00 4a 00 4b 00 49 00 } //1 UYHGDRWUIYGFIFWHIUWFHFWJKI
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}