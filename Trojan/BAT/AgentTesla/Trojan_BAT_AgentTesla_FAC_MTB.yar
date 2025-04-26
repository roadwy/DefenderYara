
rule Trojan_BAT_AgentTesla_FAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 00 73 ?? 00 00 06 25 03 6f ?? 00 00 06 00 25 07 6f ?? 00 00 06 00 0c 02 7b ?? 00 00 04 25 2d 03 26 2b 08 02 08 6f ?? 00 00 0a 00 08 6f ?? 00 00 06 0d de 16 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}