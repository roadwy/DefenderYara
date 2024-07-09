
rule Trojan_BAT_AgentTesla_EAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 00 02 6f ?? 00 00 0a 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 11 04 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 13 06 de 2c } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}