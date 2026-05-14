
rule Trojan_BAT_Zusy_BAD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 20 04 00 00 00 38 b5 ff ff ff 11 01 16 ?? ?? 00 00 0a 13 02 38 00 00 00 00 11 00 16 73 05 00 00 0a 13 09 20 01 00 00 00 7e 58 00 00 04 7b 48 00 00 04 39 88 ff ff ff 26 20 02 00 00 00 38 7d ff ff ff 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Zusy_BAD_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 73 28 00 00 0a 0c 08 07 16 73 29 00 00 0a 0d 73 1e 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 34 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 2c 06 09 6f ?? 00 00 0a dc 08 2c 06 08 6f ?? 00 00 0a dc } //3
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}