
rule Trojan_BAT_AgentTesla_MBAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 91 61 28 ?? 00 00 0a 07 11 06 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}