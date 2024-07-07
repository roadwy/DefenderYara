
rule Trojan_BAT_AgentTesla_ASG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {16 0d 2b 3d 02 09 08 90 01 05 25 26 13 04 06 12 04 90 01 05 25 26 90 01 05 06 12 04 90 01 05 25 26 90 01 05 06 12 04 90 01 05 25 26 90 01 05 09 17 d6 0d 09 02 90 01 05 25 26 32 90 00 } //1
		$a_81_1 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}