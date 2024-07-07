
rule Trojan_BAT_AgentTesla_ASCY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 90 01 01 01 00 0a 06 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 13 05 73 90 01 01 00 00 0a 0c 08 11 05 17 73 90 01 01 01 00 0a 13 04 11 04 07 16 07 8e 69 6f 90 01 01 01 00 0a 08 6f 90 01 01 01 00 0a 13 06 de 1f 90 00 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}