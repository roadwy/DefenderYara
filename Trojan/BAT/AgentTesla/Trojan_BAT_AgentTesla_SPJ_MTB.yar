
rule Trojan_BAT_AgentTesla_SPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}