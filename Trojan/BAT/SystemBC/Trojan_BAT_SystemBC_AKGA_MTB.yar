
rule Trojan_BAT_SystemBC_AKGA_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.AKGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a de 18 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}