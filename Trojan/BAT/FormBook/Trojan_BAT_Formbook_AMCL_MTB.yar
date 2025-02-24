
rule Trojan_BAT_Formbook_AMCL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 14 0d 14 13 04 [0-1e] 6f ?? 00 00 0a 00 11 04 08 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 0c 11 0c 02 16 02 8e 69 6f ?? 00 00 0a 0a de 53 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}