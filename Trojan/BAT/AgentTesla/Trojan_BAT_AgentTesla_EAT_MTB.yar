
rule Trojan_BAT_AgentTesla_EAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 06 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0d de 1e 08 2c 06 08 6f 90 01 01 00 00 0a dc 07 2c 06 07 6f 90 01 01 00 00 0a dc 06 2c 06 06 6f 90 01 01 00 00 0a dc 09 2a 90 00 } //3
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}