
rule Trojan_BAT_AgentTesla_MBKP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 06 07 06 8e 69 6a 5d d4 91 09 07 09 8e 69 6a 5d d4 91 61 28 90 01 01 00 00 0a 06 07 17 6a 58 06 8e 69 6a 5d d4 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}