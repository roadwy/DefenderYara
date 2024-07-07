
rule Trojan_BAT_AgentTesla_JGC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0d 06 09 28 90 01 03 0a 08 09 08 6f 90 01 03 0a 5d 17 d6 28 90 01 03 0a da 13 04 07 11 04 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 09 17 d6 0d 09 20 90 01 03 00 31 c7 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}