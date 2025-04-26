
rule Trojan_BAT_AgentTesla_NEAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 03 04 03 8e 69 5d 91 06 04 1f 16 5d 91 61 28 ?? 00 00 0a 03 04 17 58 03 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0b 2b 00 07 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}