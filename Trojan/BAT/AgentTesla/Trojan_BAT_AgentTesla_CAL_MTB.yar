
rule Trojan_BAT_AgentTesla_CAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 20 02 00 00 00 38 ?? ?? ?? ?? 11 04 11 00 18 5b 11 02 11 00 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 06 9c 20 03 00 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}