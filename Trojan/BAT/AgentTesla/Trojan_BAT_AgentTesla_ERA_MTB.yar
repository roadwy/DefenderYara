
rule Trojan_BAT_AgentTesla_ERA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 05 5d 03 02 05 04 28 90 01 03 06 03 04 17 58 05 5d 91 28 90 01 03 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 90 00 } //1
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 90 01 05 61 90 01 05 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}