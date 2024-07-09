
rule Trojan_BAT_AgentTesla_FAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 35 2b 1c 06 08 2b 09 06 18 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b f0 28 ?? 00 00 06 0d 2b 03 26 2b e1 06 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 13 04 de 11 0c 2b ca } //3
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}