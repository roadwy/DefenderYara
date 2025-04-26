
rule Trojan_BAT_Remcos_AMAC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 08 09 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 0b dd } //4
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}