
rule Trojan_BAT_Dnoper_ARGA_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.ARGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 f6 00 00 00 2b 32 72 ?? ?? 00 70 2b 2e 6f ?? 00 00 0a 1a 2c 21 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b de 14 08 2b cb 28 ?? 00 00 0a 2b cb } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}