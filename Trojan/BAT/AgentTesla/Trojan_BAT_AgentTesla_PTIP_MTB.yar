
rule Trojan_BAT_AgentTesla_PTIP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 24 9d 6f d0 00 00 0a 0d 72 2b 06 00 70 28 90 01 01 00 00 0a 72 61 06 00 70 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}