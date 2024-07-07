
rule Trojan_BAT_AgentTesla_BHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {0b 07 16 28 90 01 03 06 a2 07 17 28 90 01 03 06 a2 07 18 72 90 01 03 70 a2 72 90 01 03 70 28 90 01 03 0a 17 1b 8d 90 01 03 01 25 16 72 90 01 03 70 28 90 01 03 0a a2 25 17 20 00 01 00 00 8c 90 01 03 01 a2 25 1a 07 a2 28 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 61 72 72 69 78 2e 45 78 70 6c 6f 72 65 72 31 } //1 Garrix.Explorer1
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}