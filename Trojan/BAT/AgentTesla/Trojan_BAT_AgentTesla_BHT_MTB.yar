
rule Trojan_BAT_AgentTesla_BHT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 74 90 01 03 01 16 73 90 01 03 0a 0c 1a 8d 90 01 03 01 0d 07 14 72 90 01 03 70 17 8d 90 01 03 01 25 16 07 14 72 90 01 03 70 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 1b 8c 90 01 03 01 28 90 01 03 0a a2 14 14 28 90 01 03 0a 00 07 14 72 90 01 03 70 19 8d 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}