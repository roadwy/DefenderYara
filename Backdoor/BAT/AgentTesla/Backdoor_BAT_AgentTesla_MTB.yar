
rule Backdoor_BAT_AgentTesla_MTB{
	meta:
		description = "Backdoor:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {26 16 00 03 6f 90 01 02 00 0a 90 01 01 28 90 01 02 00 0a 90 01 01 3b 90 01 02 00 00 72 90 01 02 00 70 28 90 01 02 00 06 38 90 01 02 00 00 72 90 01 02 00 70 28 90 01 02 00 06 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_BAT_AgentTesla_MTB_2{
	meta:
		description = "Backdoor:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 00 06 13 05 08 72 90 01 01 00 00 70 90 0a 50 00 72 90 01 01 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 06 0c 07 90 01 05 72 90 01 01 00 00 70 28 90 01 01 00 00 06 90 01 05 28 90 01 01 00 00 06 0d 08 72 90 01 01 00 00 70 28 90 01 01 00 00 06 13 04 08 72 90 01 01 00 00 70 28 90 01 01 00 00 06 13 05 08 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_BAT_AgentTesla_MTB_3{
	meta:
		description = "Backdoor:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {a2 25 17 11 04 7b 90 01 01 00 00 04 a2 25 90 0a 50 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 0a 06 72 90 01 02 00 70 6f 90 01 01 00 00 0a 0b 07 72 90 01 02 00 70 6f 90 01 01 00 00 0a 0c 07 28 90 01 01 00 00 0a 0d 73 90 01 01 00 00 06 13 90 01 01 1f 90 01 01 8d 90 01 01 00 00 01 25 16 11 04 7b 90 01 01 00 00 04 a2 25 17 11 04 7b 90 01 01 00 00 04 a2 25 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}