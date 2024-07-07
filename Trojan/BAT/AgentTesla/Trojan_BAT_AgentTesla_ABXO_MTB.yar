
rule Trojan_BAT_AgentTesla_ABXO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 00 4a 00 47 00 4e 00 45 00 44 00 4b 00 48 00 47 00 4e 00 46 00 45 00 49 00 4b 00 48 00 20 00 4a 00 4b 00 45 00 48 00 4a 00 4b 00 4c 00 52 00 48 00 4a 00 4b 00 45 00 52 00 48 00 45 00 4a 00 4b 00 20 00 52 00 48 00 4a 00 45 00 4b 00 4c 00 48 00 52 00 4a 00 4b 00 4c 00 45 00 48 00 52 00 4c 00 4b 00 4a 00 45 00 52 00 48 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}