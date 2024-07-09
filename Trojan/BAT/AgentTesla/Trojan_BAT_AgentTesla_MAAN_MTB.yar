
rule Trojan_BAT_AgentTesla_MAAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 13 11 14 9a 13 0b 11 09 11 0b 6f ?? 00 00 0a 11 14 17 58 13 14 11 14 11 13 8e 69 32 e2 } //1
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 } //1 System.Environment
		$a_01_2 = {45 00 78 00 69 00 74 00 } //1 Exit
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}