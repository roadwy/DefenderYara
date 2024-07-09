
rule Trojan_BAT_AgentTesla_GPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 5d 13 ?? 07 11 ?? 91 11 ?? 09 1f ?? 5d 91 61 13 ?? 07 11 ?? 11 ?? 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}