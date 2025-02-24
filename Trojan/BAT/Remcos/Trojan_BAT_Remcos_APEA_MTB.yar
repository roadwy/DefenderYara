
rule Trojan_BAT_Remcos_APEA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.APEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 2b 25 72 ?? ?? 00 70 2b 21 2b 26 2b 2b 72 ?? ?? 00 70 2b 27 2b 2c 2b 31 2b 32 06 16 06 8e 69 6f ?? 00 00 0a 0c de 45 07 2b d8 28 ?? ?? 00 0a 2b d8 6f ?? 00 00 0a 2b d3 07 2b d2 28 ?? ?? 00 0a 2b d2 6f ?? ?? 00 0a 2b cd 07 2b cc 6f ?? ?? 00 0a 2b c7 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}