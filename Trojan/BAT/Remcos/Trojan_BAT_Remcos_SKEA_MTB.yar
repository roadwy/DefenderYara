
rule Trojan_BAT_Remcos_SKEA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 73 02 00 00 0a 13 05 73 03 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 05 00 00 0a 13 07 11 07 08 16 08 8e 69 6f ?? 00 00 0a 17 0b 11 06 6f ?? 00 00 0a 13 08 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}