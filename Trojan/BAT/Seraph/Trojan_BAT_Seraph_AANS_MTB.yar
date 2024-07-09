
rule Trojan_BAT_Seraph_AANS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AANS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 14 0b 2b 0c 00 28 ?? 00 00 06 0b de 03 26 de 00 07 2c f1 73 ?? 00 00 0a 0c 07 73 ?? 00 00 0a 13 04 11 04 11 07 16 73 ?? 00 00 0a 13 05 11 05 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a de 1e 11 05 6f ?? 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}